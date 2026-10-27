# Agent Posture Guard (`posture-guard`)

[![CI](https://github.com/cjprybol/agent-posture-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/cjprybol/agent-posture-guard/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![RFC 8032 Ed25519](https://img.shields.io/badge/crypto-RFC%208032%20Ed25519-success)](https://datatracker.ietf.org/doc/html/rfc8032)
[![Consultant Pilot](https://img.shields.io/badge/pilot-early%20access-brightgreen)](https://cjprybol.github.io/app-portfolio-landing-pages/agent-posture-guard/)

**Prove to every client that your coding agents never crossed their IP boundary — and reconcile per-client token & seat spend onto invoices.**

`agent-posture-guard` is a zero-dependency Python CLI (`MIT` open-source core) for fractional CTOs, multi-client AI engineering consultants, and boutique software studios running Claude Code, Codex, Cursor, and Gemini across multiple client repositories on shared workstations.

---

## Sample Client Attestation Receipt

```text
Attestation ID : att_2026_10_26_9f31c8a2 (Ed25519 signed)
Client Scope   : acme-payments-api (branch: feat/idempotency-keys, commit: a1b2c3d4)
Quarantined    : 6 sibling workspace repos blocked · external memory bank = OFF (ZDR)
Session Usage  : 4.2 agent-hrs · $18.40 API burn · 12 min human review
Public Key     : d75a980182b10ab7d54bfed3...
Status         : ZERO_CROSS_REPO_READS_VERIFIED
```

---

## What It Solves

1. **Local Clean-Room & Worktree Guard (`100%` Free MIT CLI):**
   - Verifies that the active git worktree sits strictly inside `allowed_paths` and outside `quarantined_paths`.
   - Inspects live OS file descriptors (`lsof`) to catch cross-repo bridge hazards and concurrent agent worktree collisions.
   - Verifies Zero-Data-Retention (`ZDR`) / external memory-bank isolation (`HINDSIGHT_*`, `OPENAI_STORE`, prompt-logging env flags).
2. **RFC 8032 Ed25519 Signed Session Attestations (Consultant / Studio Pack):**
   - Issues tamper-evident JSON + human-readable receipts (`att_YYYY_MM_DD_<hash>`) signed with standard **RFC 8032 Ed25519** keys (`posture-guard verify receipt.json`).
   - **Zero Cross-Client Name Leakage:** Sibling quarantined repo paths are committed via salted `SHA-256` hashes so Client A gets verifiable proof that `N sibling workspace repos` were blocked without ever seeing Client B's name.
3. **Invoice-Ready Per-Client Token & Seat Attribution (`invoice-export`):**
   - Aggregates JSONL session records by `client_scope` and `YYYY-MM` period into a clean CSV retainer appendix reconciling agent hours, API token burn, allocated seat cost, and human review minutes.

---

## Quickstart

```bash
# Clone and install locally
git clone https://github.com/cjprybol/agent-posture-guard.git
cd agent-posture-guard
pip install .

# 1. Run local clean-room & collision check (100% free MIT guard)
posture-guard scan --policy posture-policy.json

# 2. Generate Ed25519 signing key & issue signed session receipt
posture-guard keygen --secret-out ~/.config/posture-guard/ed25519.secret.key
posture-guard attest \
  --policy posture-policy.json \
  --secret-key ~/.config/posture-guard/ed25519.secret.key \
  --agent-hours 4.2 \
  --api-burn-usd 18.40 \
  --human-minutes 12 \
  --ledger sessions.jsonl \
  --output-json att_receipt.json

# 3. Verify receipt offline & export monthly client invoice CSV
posture-guard verify att_receipt.json
posture-guard invoice-export --ledger sessions.jsonl --period 2026-10 --output-csv invoice_2026_10.csv
```

---

## Sample Invoice CSV Output

```csv
period_month,client_scope,sessions_count,agent_hours_total,api_burn_usd_total,allocated_seat_usd_total,total_reimbursable_compute_usd,human_review_minutes_total,attestation_ids
2026-10,acme-payments-api,4,12.50,48.20,50.00,98.20,35.0,att_2026_10_20_1a2b;att_2026_10_22_3c4d;att_2026_10_24_5e6f;att_2026_10_26_9f31
```

---

## Consultant & Studio Pilot Access

- **Free MIT Developer CLI:** Unlimited local `scan`, `keygen`, `verify`, and preview receipts.
- **Multi-Client Consultant Pack (`$79/mo`):** Unwatermarked client-invoiceable attestation bundles, multi-client retainer CSV/Markdown exports, and priority updates.
- **Studio Team Pack (`$199/mo`):** Centralized team allowlists and SOC2/client security questionnaire exports.
  - [Reserve pilot access on the landing page](https://cjprybol.github.io/app-portfolio-landing-pages/agent-posture-guard/)

---

## Technical Scope Notice

Agent Posture Guard records process, filesystem-allowlist, and API-telemetry evidence configured on the host OS. Technical attestations document observed runtime boundaries and do not constitute legal opinions or third-party audit certifications.
