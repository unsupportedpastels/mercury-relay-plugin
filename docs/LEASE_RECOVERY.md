# Retained lease recovery v1

This extension is opt-in: encrypted `controller.open` includes
`"recovery_version":1`. Unknown versions reject. Legacy/iOS admission without
this field keeps its existing preamble and exact raw Hermes frame wire.

A v1 open reattaches the authorized device's existing, detached lease. A
wrong-profile or already-attached lease rejects rather than replacing accepted
work. A missing lease creates a new controller; when `resume_cursor` was supplied,
`recovery_reset:true` explicitly signals loss of the old runtime. App process
launch should use cursor 0 unless it durably checkpointed both cursor and reducer
state. Authorization, authorization epoch, and current profile availability are
checked again at admission; no recovery RPC discovers or resurrects computation.

## Lease channels (several sessions per device)

`controller.open` may carry `"channel"`: 1–64 characters of `[A-Za-z0-9_-]`.
The host keeps **one lease per (device, channel)**, so a client that opens one
channel per session runs several Hermes sessions at once over separate device
sockets (the router multiplexes them). Rules:

- No `channel` field is the default channel `""` and keeps the legacy
  behaviour: a fresh open supersedes the device's retained default lease only.
- A fresh open on a named channel supersedes only that channel's retained
  lease; other channels are untouched.
- Reattach (`resume_cursor` / `recovery_version`) looks up the lease by
  (device, channel).
- Revocation and an authorization-epoch change release every channel the
  device holds. Total leases per host stay bounded by `max_controllers`.
- Durable recovery rows for a named channel are scoped as
  `<device_id>/<channel>`; default-channel rows keep the bare device id.

## Wire

The first notification is `relay.lease.attached`. Existing `last_seq`,
`replay_gap`, `replayed_from`, and `resume_cursor` fields remain. V1 adds:

- `recovery_version:1`, opaque immutable `lease_id`, `recovery_reset`.
- `snapshot_through`: lease sequence at snapshot capture, **not an acknowledgment**.
- `bindings`: bounded `{runtime_session_id,durable_session_id,profile,live}` rows.
- `task_snapshot`: bounded original-shaped `method:"event"` child events.
- `snapshot_complete:false`: observed events cannot prove a complete inventory.
- `snapshot_truncated`: row, byte, retention or observation loss.

Bound task snapshot `params` additionally carry `durable_session_id`, `profile`,
`relay_event_id` (`projection:<revision>`), `recovery_revision`, and
`recovery_binding` (same shape as a bindings row). These fields are plugin
projections; original Hermes frames are not rewritten. No `observed_at_ms` is
currently supplied. Unbound observations omit ownership fields; clients must
not import them without independently proven runtime/durable/profile ownership.

Every retained v1 frame is wrapped:

```json
{"jsonrpc":"2.0","method":"relay.lease.frame","params":{"lease_id":"opaque-id","seq":1,"replay":false,"frame":"<exact original Hermes JSON string>"}}
```

The sequence belongs to the lease, **not** Hermes events or Noise nonces. Buffered
replay sets `replay:true`. After replay, including empty replay, an ordered
`relay.lease.replay_complete` notification carries `{lease_id,last_seq}` before
live delivery. A cursor advances only after applying the corresponding frame.
Plain local read and duplicate-submission responses do not advance it.

Clients must discard replayed RPC responses and namespace RPC request IDs by
attachment generation: a still-in-flight original inner request can finish
*after* reattach and arrive as a live frame. Local read/dedup responses are also
fenced in the plugin to their initiating attachment. Do not retry mutations
blindly; `prompt.submit` uses existing bounded `submission_id` deduplication.

## Durable observations, not durable computation

`lease-recovery.json` lives in the installation plugin's private agent directory.
It is separate from authorization state, the streaming ring, and diagnostics.
The existing owner-private, no-symlink, atomic replace/file+directory fsync
helpers commit projections before bound child events enter delivery. Failures
fail closed with sanitized transport failures, not fabricated terminal evidence.

Durable keys contain installation identity (hex), device authorization epoch,
actual explicitly requested profile, durable session, and child identity.
Bindings come **only** from successfully permitted `session.create`/
`session.resume` request/response observations (`stored_session_id` or
`session_key` in Hermes results). A conflicting response profile is not trusted.
No global delegation registry, private core session state, discovery resume, or
Hermes/router modifications are used.

Explicit child terminal statuses remain sticky, including after in-memory
snapshot eviction. Goal/action/tool/summary fields are bounded and merged.
Parent completion, an absent child, expired evidence, and plugin restart never
imply child success. Historical nonterminal rows reload as `status:"unknown"`;
historical bindings use `live:false`. Retained runtime bindings use `live:true`.
Unbound children cannot be durably attributed until a permitted response proves
the binding; a crash before that observation is an explicitly incomplete case.
Only events Hermes actually emits to this controller can be projected; disabled
child progress, evicted evidence and unobserved work remain unknown.

## Bounds and release behavior

- Existing lease limits: 256 frames / 4 MiB, ten-minute frame age, five-minute
  detached TTL, at most eight installation leases by runtime default.
- V1 ring overflow drops old replay and reports a gap **without killing the
  accepted inner controller solely because replay filled**. Reconcile child
  snapshots and authoritative transcripts; do not treat a gapped stream as a
  complete foreground/approval transcript. TTL, controller close/failure,
  backpressure, revocation and explicit resource limits still apply.
- Snapshot: at most 64 tasks and 64 bindings, at most 128 KiB task JSON.
- Durable file: at most 256 rows / 2 MiB, seven-day retention. The single serve
  process owns the writer. No cross-process shared-writer guarantee.
- Eight local reads in flight. Cancellation on lease release; late results and
  duplicate waiters cannot satisfy requests on a different attachment.
- Revocation changes the authorization epoch, releases the lease, prevents queued
  snapshot/replay delivery and prunes loaded durable records. Old epochs cannot
  recover after reauthorization, even if an old file survives.

The extension preserves accepted computation only while the live inner lease
survives. Plugin shutdown/restart does not resurrect children, pending approvals,
request state, or the controller. Durable terminal evidence is reconstruction of
observations, not proof the rest of the task inventory is complete.

## Verification / activation

Focused tests cover wrapper cursors/replay/watermarks, legacy exact frames,
bounded durable store and manager recreation, Noise admission/profile/epoch
scope, terminal stickiness and memory eviction, TTL/byte truncation, ring-gap
controller survival, local-read late responses/cancellation and revocation queue
fencing. Run against the installed Hermes interpreter with its source on
`PYTHONPATH` for full contract coverage; the isolated plugin venv intentionally
skips host-contract dependencies.

Source is not activated by tests. Parent review, loaded-source/hash proof, and
Android emulator recovery E2E are separate release gates. No iOS recovery
support is claimed by this opt-in protocol.
