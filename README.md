# Agent Posture Guard (`posture-guard`)

**Prove to every client that your coding agents never crossed their IP boundary — and reconcile per-client token & seat spend onto invoices.**

`agent-posture-guard` is a zero-dependency Python CLI (`MIT` open-source core) for fractional CTOs, multi-client AI engineering consultants, and boutique software studios running Claude Code, Codex, Cursor, and Gemini across multiple client repositories on shared workstations.

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

## Quickstart

```bash
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

## Consultant & Studio Pilot Access

- **Free MIT Developer CLI:** Unlimited local `scan`, `keygen`, `verify`, and preview receipts.
- **Multi-Client Consultant Pack (`$79/mo`) & Studio Pack (`$199/mo`):** Unwatermarked client-invoiceable attestation bundles, multi-client retainer CSV/Markdown exports, and SOC2/questionnaire packs.
  - Reserve pilot access: https://cjprybol.github.io/app-portfolio-landing-pages/agent-posture-guard/

## Technical Scope Notice

Agent Posture Guard records process, filesystem-allowlist, and API-telemetry evidence configured on the host OS. Technical attestations document observed runtime boundaries and do not constitute legal opinions or third-party audit certifications.
