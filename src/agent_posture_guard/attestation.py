"""RFC 8032 Ed25519 signed session attestations and per-client invoice spend ledgers."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import secrets
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

from agent_posture_guard.ed25519_pure import (
    derive_public_key,
    sign_ed25519,
    verify_ed25519,
)
from agent_posture_guard.guard import (
    TECHNICAL_SCOPE_NOTICE,
    PosturePolicy,
    PostureScanResult,
)


def _canonical_json_bytes(payload: dict[str, object]) -> bytes:
    """Serialize payload canonically (sorted keys, compact separators) for signing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class SignedSessionAttestation:
    """Tamper-evident clean-room session attestation safe to attach to client invoices.

    Confidentiality invariant: sibling client folder names are NEVER stored in plaintext;
    only salted SHA-256 commitments (`quarantined_commitments`) and the blocked count are
    included, preventing cross-client NDA metadata leakage.
    """

    schema_version: str
    attestation_id: str
    issued_at: str
    tier_mode: str
    client_scope: str
    git_branch: str
    git_head_sha: str
    quarantined_repo_count: int
    quarantined_commitments: tuple[str, ...]
    external_memory_bank: str
    agent_hours: float
    api_burn_usd: float
    human_review_minutes: float
    status: str
    public_key_hex: str
    signature_hex: str
    scope_notice: str = TECHNICAL_SCOPE_NOTICE

    def unsigned_payload(self) -> dict[str, object]:
        data = asdict(self)
        data.pop("signature_hex", None)
        return data

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def create_signed_attestation(
    policy: PosturePolicy,
    scan: PostureScanResult,
    *,
    secret_seed: bytes,
    agent_hours: float,
    api_burn_usd: float,
    human_review_minutes: float,
    tier_mode: str = "licensed-consultant",
    issued_at: str | None = None,
    salt_hex: str | None = None,
) -> SignedSessionAttestation:
    """Create an Ed25519-signed session receipt from a verified PostureScanResult."""
    if not scan.passed:
        raise ValueError(
            "Cannot issue clean-room attestation when PostureScanResult has FAIL violations"
        )
    if agent_hours < 0 or api_burn_usd < 0 or human_review_minutes < 0:
        raise ValueError("Usage and spend metrics must be non-negative")

    ts = issued_at or datetime.now(UTC).isoformat()
    date_slug = ts[:10].replace("-", "_")
    salt = salt_hex or secrets.token_hex(8)
    commitments = tuple(
        hashlib.sha256(f"{salt}:{Path(q).resolve()}".encode("utf-8")).hexdigest()[:16]
        for q in policy.quarantined_paths
    )
    att_hash = hashlib.sha256(
        f"{ts}:{policy.client_scope}:{scan.git_head_sha}:{salt}".encode("utf-8")
    ).hexdigest()[:8]
    att_id = f"att_{date_slug}_{att_hash}"

    pub_hex = derive_public_key(secret_seed).hex()
    draft = SignedSessionAttestation(
        schema_version="posture-attestation-v1",
        attestation_id=att_id,
        issued_at=ts,
        tier_mode=tier_mode,
        client_scope=policy.client_scope,
        git_branch=scan.git_branch,
        git_head_sha=scan.git_head_sha,
        quarantined_repo_count=scan.quarantined_repo_count,
        quarantined_commitments=commitments,
        external_memory_bank="OFF (ZDR)" if scan.external_memory_bank_zdr else "ACTIVE",
        agent_hours=round(agent_hours, 2),
        api_burn_usd=round(api_burn_usd, 2),
        human_review_minutes=round(human_review_minutes, 1),
        status=scan.status_code,
        public_key_hex=pub_hex,
        signature_hex="",
    )
    sig = sign_ed25519(secret_seed, _canonical_json_bytes(draft.unsigned_payload()))
    return SignedSessionAttestation(
        **{**draft.to_dict(), "signature_hex": sig.hex()}  # type: ignore[arg-type]
    )


def verify_signed_attestation(attestation_dict: dict[str, object]) -> bool:
    """Verify Ed25519 cryptographic signature and structural integrity of a receipt dict."""
    try:
        sig_hex = str(attestation_dict["signature_hex"])
        pub_hex = str(attestation_dict["public_key_hex"])
        unsigned = {k: v for k, v in attestation_dict.items() if k != "signature_hex"}
        return verify_ed25519(
            bytes.fromhex(pub_hex),
            _canonical_json_bytes(unsigned),
            bytes.fromhex(sig_hex),
        )
    except Exception:
        return False


def format_attestation_receipt(att: SignedSessionAttestation) -> str:
    """Render concise human-readable receipt block for client retainer appendices."""
    mode_tag = "Ed25519 signed" if att.tier_mode.startswith("licensed") else "PREVIEW — EVALUATION ONLY"
    lines = [
        f"Attestation ID : {att.attestation_id} ({mode_tag})",
        f"Client Scope   : {att.client_scope} (branch: {att.git_branch}, commit: {att.git_head_sha[:8]})",
        f"Quarantined    : {att.quarantined_repo_count} sibling workspace repos blocked · external memory bank = {att.external_memory_bank}",
        f"Session Usage  : {att.agent_hours:.1f} agent-hrs · ${att.api_burn_usd:.2f} API burn · {att.human_review_minutes:.0f} min human review",
        f"Public Key     : {att.public_key_hex[:24]}...",
        f"Status         : {att.status}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Multi-Client Invoice Spend & Seat Attribution Ledger
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionSpendRecord:
    """Append-only JSONL record attributing agent seat + token spend to a client scope."""

    recorded_at: str
    period_month: str
    client_scope: str
    attestation_id: str
    agent_hours: float
    api_burn_usd: float
    allocated_seat_usd: float
    human_review_minutes: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def append_spend_record(ledger_path: Path, record: SessionSpendRecord) -> None:
    if (
        record.agent_hours < 0
        or record.api_burn_usd < 0
        or record.allocated_seat_usd < 0
        or record.human_review_minutes < 0
    ):
        raise ValueError("Spend ledger amounts and durations must be non-negative")
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")


def load_spend_records(ledger_path: Path) -> list[SessionSpendRecord]:
    if not ledger_path.exists():
        return []
    out: list[SessionSpendRecord] = []
    for raw in ledger_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        d = json.loads(raw)
        out.append(
            SessionSpendRecord(
                recorded_at=str(d["recorded_at"]),
                period_month=str(d["period_month"]),
                client_scope=str(d["client_scope"]),
                attestation_id=str(d["attestation_id"]),
                agent_hours=float(d["agent_hours"]),
                api_burn_usd=float(d["api_burn_usd"]),
                allocated_seat_usd=float(d["allocated_seat_usd"]),
                human_review_minutes=float(d["human_review_minutes"]),
            )
        )
    return out


def export_client_invoice_csv(
    records: Sequence[SessionSpendRecord],
    *,
    period_month: str,
    client_scope: str | None = None,
) -> str:
    """Export per-client invoice attribution CSV filtered by period_month (and optional client)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "period_month",
            "client_scope",
            "sessions_count",
            "agent_hours_total",
            "api_burn_usd_total",
            "allocated_seat_usd_total",
            "total_reimbursable_compute_usd",
            "human_review_minutes_total",
            "attestation_ids",
        ]
    )

    grouped: dict[str, list[SessionSpendRecord]] = defaultdict(list)
    for rec in records:
        if rec.period_month != period_month:
            continue
        if client_scope is not None and rec.client_scope != client_scope:
            continue
        grouped[rec.client_scope].append(rec)

    for scope in sorted(grouped):
        rows = grouped[scope]
        hrs = sum(r.agent_hours for r in rows)
        api = sum(r.api_burn_usd for r in rows)
        seat = sum(r.allocated_seat_usd for r in rows)
        h_mins = sum(r.human_review_minutes for r in rows)
        ids = ";".join(r.attestation_id for r in rows)
        writer.writerow(
            [
                period_month,
                scope,
                len(rows),
                f"{hrs:.2f}",
                f"{api:.2f}",
                f"{seat:.2f}",
                f"{api + seat:.2f}",
                f"{h_mins:.1f}",
                ids,
            ]
        )
    return buf.getvalue()
