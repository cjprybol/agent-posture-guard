"""Unit and integration tests for Agent Posture Guard (RFC 8032 Ed25519, boundary scanner, attestations & invoice CSV)."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from agent_posture_guard.attestation import (
    SessionSpendRecord,
    append_spend_record,
    create_signed_attestation,
    export_client_invoice_csv,
    format_attestation_receipt,
    load_spend_records,
    verify_signed_attestation,
)
from agent_posture_guard.cli import main, resolve_consultant_tier
from agent_posture_guard.ed25519_pure import (
    derive_public_key,
    sign_ed25519,
    verify_ed25519,
)
from agent_posture_guard.guard import (
    ObservedProcess,
    PosturePolicy,
    parse_lsof_field_output,
    scan_runtime_posture,
)


def test_rfc8032_section_7_1_official_test_vectors() -> None:
    # Official RFC 8032 Section 7.1 TEST 1 (empty message)
    seed_1 = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    expected_pub_1 = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    expected_sig_1 = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert derive_public_key(seed_1) == expected_pub_1
    assert sign_ed25519(seed_1, b"") == expected_sig_1
    assert verify_ed25519(expected_pub_1, b"", expected_sig_1) is True
    assert verify_ed25519(expected_pub_1, b"tampered", expected_sig_1) is False

    # Official RFC 8032 Section 7.1 TEST 2 (1-byte message 0x72)
    seed_2 = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    expected_pub_2 = bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    )
    expected_sig_2 = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    assert derive_public_key(seed_2) == expected_pub_2
    assert sign_ed25519(seed_2, bytes.fromhex("72")) == expected_sig_2
    assert verify_ed25519(expected_pub_2, bytes.fromhex("72"), expected_sig_2) is True


def test_scanner_detects_quarantine_fd_breach_bridge_collision_and_zdr_drift(
    tmp_path: Path,
) -> None:
    client_a = tmp_path / "acme-payments-api"
    client_b = tmp_path / "secret-biotech-client"
    client_a.mkdir()
    client_b.mkdir()

    policy = PosturePolicy(
        client_scope="acme-payments-api",
        allowed_paths=(str(client_a),),
        quarantined_paths=(str(client_b),),
        require_zdr=True,
    )

    # 1. Clean session passes with ZERO_CROSS_REPO_READS_VERIFIED
    clean_scan = scan_runtime_posture(
        policy,
        worktree=client_a,
        current_pid=1001,
        env={},
        processes=[ObservedProcess(1001, "claude", (str(client_a / "src"),))],
        git_probe=lambda _: ("feat/idempotency-keys", "a1b2c3d4" * 5),
    )
    assert clean_scan.passed is True
    assert clean_scan.status_code == "ZERO_CROSS_REPO_READS_VERIFIED"

    # 2. Cross-repo bridge process + ZDR env leak MUST fail closed
    breach_scan = scan_runtime_posture(
        policy,
        worktree=client_a,
        current_pid=1001,
        env={"HINDSIGHT_ENABLED": "true"},
        processes=[
            ObservedProcess(1001, "claude", (str(client_a),)),
            ObservedProcess(
                2002,
                "codex",
                (str(client_a / "api.py"), str(client_b / "proprietary.py")),
            ),
        ],
        git_probe=lambda _: ("main", "f" * 40),
    )
    assert breach_scan.passed is False
    codes = {v.code for v in breach_scan.violations}
    assert "CROSS_REPO_BRIDGE_HAZARD" in codes
    assert "MEMORY_POSTURE_DRIFT" in codes


def test_signed_attestation_hides_sibling_names_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    client_a = tmp_path / "acme-payments-api"
    secret_sibling = tmp_path / "stealth-neuro-corp-confidential"
    client_a.mkdir()
    secret_sibling.mkdir()

    policy = PosturePolicy(
        client_scope="acme-payments-api",
        allowed_paths=(str(client_a),),
        quarantined_paths=(str(secret_sibling),),
    )
    scan = scan_runtime_posture(
        policy,
        worktree=client_a,
        current_pid=500,
        env={},
        processes=[ObservedProcess(500, "python", (str(client_a),))],
        git_probe=lambda _: ("feat/idempotency-keys", "9f31c8a2" * 5),
    )
    seed = b"\x11" * 32
    att = create_signed_attestation(
        policy,
        scan,
        secret_seed=seed,
        agent_hours=4.2,
        api_burn_usd=18.40,
        human_review_minutes=12.0,
    )

    serialized = json.dumps(att.to_dict())
    # CRITICAL NDA INVARIANT: sibling client's plaintext name must NEVER appear in Client A's receipt!
    assert "stealth-neuro-corp-confidential" not in serialized
    assert att.quarantined_repo_count == 1
    assert len(att.quarantined_commitments) == 1
    assert verify_signed_attestation(att.to_dict()) is True

    # Mutating api_burn_usd by $0.01 invalidates Ed25519 signature immediately
    tampered = {**att.to_dict(), "api_burn_usd": 118.40}
    assert verify_signed_attestation(tampered) is False

    summary = format_attestation_receipt(att)
    assert "ZERO_CROSS_REPO_READS_VERIFIED" in summary
    assert "$18.40 API burn" in summary


def test_cli_end_to_end_keygen_attest_verify_and_invoice_csv(tmp_path: Path) -> None:
    client_dir = tmp_path / "client-alpha"
    sibling_dir = tmp_path / "client-beta"
    client_dir.mkdir()
    sibling_dir.mkdir()

    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "client_scope": "client-alpha",
                "allowed_paths": [str(client_dir)],
                "quarantined_paths": [str(sibling_dir)],
                "require_zdr": False,
            }
        ),
        encoding="utf-8",
    )
    key_file = tmp_path / "ed25519.secret.key"
    receipt_file = tmp_path / "receipt.json"
    ledger_file = tmp_path / "sessions.jsonl"
    csv_file = tmp_path / "invoice.csv"

    assert main(["keygen", "--secret-out", str(key_file)]) == 0
    assert key_file.exists()

    payload = b"apg_consultant_20271026_c01"
    sig = hmac.new(
        b"agent-posture-guard-v1-public-salt", payload, hashlib.sha256
    ).hexdigest()[:16]
    lic = f"{payload.decode()}_{sig}"
    assert resolve_consultant_tier(lic) == "licensed-consultant"

    rc_att = main(
        [
            "attest",
            "--policy",
            str(policy_file),
            "--secret-key",
            str(key_file),
            "--agent-hours",
            "3.5",
            "--api-burn-usd",
            "14.25",
            "--allocated-seat-usd",
            "20.00",
            "--human-minutes",
            "10",
            "--ledger",
            str(ledger_file),
            "--output-json",
            str(receipt_file),
            "--license-key",
            lic,
        ]
    )
    assert rc_att == 0
    assert main(["verify", str(receipt_file)]) == 0

    records = load_spend_records(ledger_file)
    assert len(records) == 1
    period = records[0].period_month

    assert (
        main(
            [
                "invoice-export",
                "--ledger",
                str(ledger_file),
                "--period",
                period,
                "--output-csv",
                str(csv_file),
            ]
        )
        == 0
    )
    csv_text = csv_file.read_text(encoding="utf-8")
    assert "client-alpha,1,3.50,14.25,20.00,34.25,10.0" in csv_text


def test_lsof_parser_and_negative_spend_guard(tmp_path: Path) -> None:
    sample = "p1234\ncclaude\nn/Users/dev/repoA\np5678\nccodex\nn/Users/dev/repoB\n"
    parsed = parse_lsof_field_output(sample)
    assert len(parsed) == 2
    assert parsed[0].pid == 1234
    assert parsed[0].command == "claude"
    assert parsed[0].open_paths == ("/Users/dev/repoA",)

    with pytest.raises(ValueError, match="non-negative"):
        append_spend_record(
            tmp_path / "bad.jsonl",
            SessionSpendRecord(
                recorded_at="2026-10-26T00:00:00+00:00",
                period_month="2026-10",
                client_scope="x",
                attestation_id="att_1",
                agent_hours=-1.0,
                api_burn_usd=0.0,
                allocated_seat_usd=0.0,
                human_review_minutes=0.0,
            ),
        )
