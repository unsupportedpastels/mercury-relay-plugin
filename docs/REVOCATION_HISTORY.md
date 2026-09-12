# Bounded revocation history and recovery

Pairing has three independent limits:

- **5 active devices** (pending plus authorized), unchanged.
- **16 full device records**, including recent denied/revoked history.
- **512 compact revoked-key digests**, separate from the full records.

When a new pairing needs a record slot, the repository first prunes denied
history. If necessary, it replaces the oldest full revoked record with the
canonical base64 encoding of SHA-256 of its full device public key. The compact
evidence and record removal are persisted together in the existing locked,
atomic state transaction. Evidence is deduplicated and is never aged out or
evicted. Every pairing checks both full revoked records and compact evidence;
a revoked key cannot silently re-pair after history compaction or restart.
Archived records no longer appear in `list_devices`; their keys remain banned.

This fixes the 16-revocations pairing dead end without unbounded storage or
forgetting revoked keys. The existing 64 KiB state-file ceiling is unchanged.
It is deliberately **not unlimited lifetime revocation capacity**: exact evidence
has a finite budget. If no denied record can be pruned and no revoked record can
be safely compacted, new pairing fails closed. Existing devices can still be
revoked because their full records retain the evidence without using an archive
slot. Existing authorizations are not cleared automatically.

## State compatibility

Existing schema-v1 state is read without migration until revoked history first
needs compaction. That transaction upgrades only the private authorization state
to **schema v2**, with a required `revoked_key_digests` list. Identity and the
remaining device records are preserved. Public configuration and connection
journal formats remain v1.

Older plugin versions reject schema v2 instead of ignoring compact evidence.
Do not edit the version back to 1, remove evidence, or restore a pre-revocation
backup to make a downgrade work: those actions would undo security decisions.
Upgrade every process sharing the profile before using compacted state.

## Explicit owner recovery at the safety ceiling

Local `create_offer` reports:

> revocation history full; retain this state and use a new relay profile

Recovery means an **owner-approved new trust domain**, not clearing this
installation's deny history:

1. Stop the old profile's relay and retain its private state securely, including
   all revocation evidence. Do not delete or reset that state in place.
2. Create a separate relay profile with a newly generated installation identity.
   Do not copy the old profile's identity, authorization state, or pairing offers.
3. Re-pair only devices the owner explicitly trusts, verifying the new host and
   pairing fingerprint out of band. Previously compromised devices must be
   remediated and re-keyed before the owner considers trusting them again.
4. Keep the old profile disabled. Its revoked keys remain rejected if its state
   is inspected or used with a compatible plugin.

No automatic recovery/reset API is provided: changing installation identity and
re-establishing trust requires an explicit owner decision.
