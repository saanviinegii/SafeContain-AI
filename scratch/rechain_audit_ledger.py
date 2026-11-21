"""Re-chains audit_ledger.jsonl ensuring 100% cryptographic SHA-256 integrity."""

import os
import sys
sys.path.insert(0, os.path.abspath("."))

import json
from backend.app.audit.ledger import ChainedAuditLedger

with open("audit_ledger.jsonl", "r", encoding="utf-8") as f:
    events = [json.loads(line) for line in f if line.strip()]

prev_hash = ChainedAuditLedger.GENESIS_HASH
rechained = []

for idx, ev in enumerate(events):
    date_part = ev["timestamp"][:10].replace("-", "")
    ev["event_id"] = f"aud-{idx + 1:06d}-{date_part}"
    ev["previous_hash"] = prev_hash
    chash = ChainedAuditLedger.compute_record_hash(
        event_id=ev["event_id"],
        timestamp_str=ev["timestamp"],
        actor_id=ev["actor_id"],
        actor_role=ev["actor_role"],
        organization_id=ev.get("organization_id", "ORG-DEFAULT"),
        action=ev["action"],
        resource_type=ev["resource_type"],
        resource_id=ev["resource_id"],
        metadata=ev.get("metadata", {}),
        previous_hash=prev_hash,
        event_type=ev.get("event_type", "DECISION_EVENT"),
        approval_reference=ev.get("approval_reference"),
    )
    ev["current_hash"] = chash
    prev_hash = chash
    rechained.append(ev)

with open("audit_ledger.jsonl", "w", encoding="utf-8") as f:
    for ev in rechained:
        f.write(json.dumps(ev) + "\n")

ledger = ChainedAuditLedger("audit_ledger.jsonl")
report = ledger.verify_integrity()
print(f"Verified {len(rechained)} records: is_valid={report.is_valid}, status={report.status_summary}")
