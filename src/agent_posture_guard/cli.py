"""CLI entrypoint for Agent Posture Guard (`posture-guard`)."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

from agent_posture_guard.attestation import (
    SessionSpendRecord,
    append_spend_record,
    create_signed_attestation,
    export_client_invoice_csv,
    format_attestation_receipt,
    load_spend_records,
    verify_signed_attestation,
)
from agent_posture_guard.ed25519_pure import derive_public_key
from agent_posture_guard.guard import (
    PILOT_RESERVATION_URL,
    PosturePolicy,
    scan_runtime_posture,
)


def resolve_consultant_tier(license_key: str | None = None) -> str:
    """Validate optional Consultant ($79/mo) / Studio ($199/mo) license key."""
    raw = (license_key or os.environ.get("POSTURE_GUARD_LICENSE_KEY") or "").strip()
    if not raw:
        return "oss-preview"
    parts = raw.split("_")
    if len(parts) == 5 and parts[0] == "apg" and parts[1] in {"consultant", "studio"}:
        payload = "_".join(parts[:4]).encode("utf-8")
        salt = os.environ.get(
            "POSTURE_GUARD_SIGNING_PUBLIC_SALT", "agent-posture-guard-v1-public-salt"
        ).encode("utf-8")
        expected = hmac.new(salt, payload, hashlib.sha256).hexdigest()[:16]
        if hmac.compare_digest(parts[4], expected):
            return f"licensed-{parts[1]}"
    return "oss-preview"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="posture-guard",
        description="Multi-client clean-room boundary scanner & Ed25519 attestation CLI.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # 1. Free MIT local boundary & collision scan
    p_scan = sub.add_parser("scan", help="Scan host processes, worktree & ZDR env against policy")
    p_scan.add_argument("--policy", type=Path, required=True, help="Path to posture-policy.json")
    p_scan.add_argument("--worktree", type=Path, default=None, help="Override active worktree path")
    p_scan.add_argument("--output-json", type=Path, default=None, help="Write JSON scan report")

    # 2. Ed25519 keypair generation
    p_key = sub.add_parser("keygen", help="Generate 32-byte Ed25519 signing seed & public key")
    p_key.add_argument("--secret-out", type=Path, required=True, help="Path to write hex seed")

    # 3. Signed clean-room session attestation
    p_att = sub.add_parser("attest", help="Issue an Ed25519-signed clean-room session receipt")
    p_att.add_argument("--policy", type=Path, required=True)
    p_att.add_argument("--secret-key", type=Path, required=True)
    p_att.add_argument("--agent-hours", type=float, default=1.0)
    p_att.add_argument("--api-burn-usd", type=float, default=0.0)
    p_att.add_argument("--allocated-seat-usd", type=float, default=0.0)
    p_att.add_argument("--human-minutes", type=float, default=0.0)
    p_att.add_argument("--output-json", type=Path, required=True)
    p_att.add_argument("--ledger", type=Path, default=None, help="Optional spend JSONL ledger")
    p_att.add_argument("--license-key", type=str, default=None)

    # 4. Offline Ed25519 signature verification
    p_ver = sub.add_parser("verify", help="Verify an Ed25519 session attestation JSON file")
    p_ver.add_argument("receipt_json", type=Path)

    # 5. Per-client invoice CSV export
    p_inv = sub.add_parser("invoice-export", help="Export per-client compute & review CSV")
    p_inv.add_argument("--ledger", type=Path, required=True)
    p_inv.add_argument("--period", type=str, required=True, help="Billing period YYYY-MM")
    p_inv.add_argument("--client-scope", type=str, default=None)
    p_inv.add_argument("--output-csv", type=Path, required=True)

    args = parser.parse_args(argv)

    if args.command == "keygen":
        seed = secrets.token_bytes(32)
        pub = derive_public_key(seed)
        args.secret_out.parent.mkdir(parents=True, exist_ok=True)
        args.secret_out.write_text(seed.hex() + "\n", encoding="utf-8")
        try:
            os.chmod(args.secret_out, 0o600)
        except OSError:
            pass
        print(f"Public key (Ed25519 hex): {pub.hex()}")
        return 0

    if args.command == "scan":
        policy = PosturePolicy.from_file(args.policy)
        res = scan_runtime_posture(policy, worktree=args.worktree)
        print(f"[{res.status_code}] client={res.client_scope} quarantined={res.quarantined_repo_count}")
        for v in res.violations:
            print(f"  [{v.severity}] {v.code}: {v.detail}")
        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(json.dumps(res.to_dict(), indent=2), encoding="utf-8")
        return 0 if res.passed else 1

    if args.command == "attest":
        policy = PosturePolicy.from_file(args.policy)
        scan = scan_runtime_posture(policy)
        if not scan.passed:
            print("Error: clean-room posture scan failed; refusing to sign attestation.", file=sys.stderr)
            return 1
        seed = bytes.fromhex(args.secret_key.read_text(encoding="utf-8").strip())
        tier = resolve_consultant_tier(args.license_key)
        att = create_signed_attestation(
            policy,
            scan,
            secret_seed=seed,
            agent_hours=args.agent_hours,
            api_burn_usd=args.api_burn_usd,
            human_review_minutes=args.human_minutes,
            tier_mode=tier,
        )
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(att.to_dict(), indent=2), encoding="utf-8")
        print(format_attestation_receipt(att))
        if tier == "oss-preview":
            print(
                f"\n[Preview Mode] Upgrade to Consultant Pack ($79/mo) for unwatermarked client-invoiceable receipts: {PILOT_RESERVATION_URL}"
            )
        if args.ledger is not None:
            now_iso = datetime.now(UTC).isoformat()
            append_spend_record(
                args.ledger,
                SessionSpendRecord(
                    recorded_at=now_iso,
                    period_month=now_iso[:7],
                    client_scope=policy.client_scope,
                    attestation_id=att.attestation_id,
                    agent_hours=args.agent_hours,
                    api_burn_usd=args.api_burn_usd,
                    allocated_seat_usd=args.allocated_seat_usd,
                    human_review_minutes=args.human_minutes,
                ),
            )
        return 0

    if args.command == "verify":
        data = json.loads(args.receipt_json.read_text(encoding="utf-8"))
        ok = verify_signed_attestation(data)
        print("VERIFIED_ED25519_OK" if ok else "INVALID_SIGNATURE")
        return 0 if ok else 1

    if args.command == "invoice-export":
        records = load_spend_records(args.ledger)
        csv_text = export_client_invoice_csv(
            records, period_month=args.period, client_scope=args.client_scope
        )
        args.output_csv.parent.mkdir(parents=True, exist_ok=True)
        args.output_csv.write_text(csv_text, encoding="utf-8")
        print(f"Wrote client invoice attribution CSV to {args.output_csv}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
