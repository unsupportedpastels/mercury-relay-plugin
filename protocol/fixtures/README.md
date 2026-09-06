# Hermes contract fixtures — policy

**Status:** Phase 0 policy; fixtures are synthetic and local-only
**Inventory:** the Relay v1 Hermes method allow-list is enforced in `src/mercury_relay_plugin/method_policy.py`
**Purpose:** make the narrow Mercury Relay v1 Hermes boundary executable without storing user traffic, credentials, or deployment metadata

This directory is for sanitized compatibility fixtures at the official Hermes boundary. It is not a capture dump, a place for real transcripts, or a second Hermes protocol. A fixture must be reproducible from synthetic inputs and must preserve the exact Hermes method names, fields, query semantics, event order, and text values described in the inventory.

## 1. Authority and provenance

The fixture oracle is the combination of:

1. the current Hermes Agent source checkout;
2. the current Mercury iOS and Android client source checkout;
3. `src/mercury_relay_plugin/method_policy.py`, which freezes the Relay v1 allow-list.

Every fixture or fixture manifest must record `source_refs` with an exact repository-relative source path and symbol, for example:

```json
{
  "source_refs": [
    {
      "path": "hermes_cli/web_routers/profiles.py",
      "symbol": "get_profiles_sessions"
    },
    {
      "path": "tui_gateway/methods_session.py",
      "symbol": "@method(\"session.resume\")"
    }
  ]
}
```

Do not record a live host, checkout-specific absolute path, branch URL, access token, or captured request header as provenance. The source paths in the example identify code, not a deployment.

## 2. Required fixture metadata

Each fixture family has a small manifest (or equivalent checked-in metadata) with these fields:

| Field | Requirement |
|---|---|
| `fixture_schema` | Integer policy version. Increment only for a fixture-format breaking change. |
| `surface` | One of `http`, `ws`, or `rpc`. A bundle manifest spanning multiple fixture files uses the exact `surfaces` list while each indexed fixture retains its singular `surface`. |
| `scenario` | Stable synthetic scenario name; no user/session data. |
| `source_refs` | One or more exact `{path, symbol}` references. |
| `profile` | Synthetic profile scope, normally `default` or `fixture_profile`; never a real profile. |
| `synthetic` | Must be `true`. |
| `contains_secrets` | Must be `false`. |
| `contains_live_hosts` | Must be `false`. |
| `expected` | Bounded outcome such as `success`, `expired`, `rejected`, or `oversize`. |

The manifest may record byte/character counts and a digest of deterministic filler. It must not echo the filler, a response body that contains secrets, or raw exception text.

## 3. Synthetic data rules

- Use obvious non-production identifiers such as `fixture-durable-001`, `fixture-runtime-001`, `fixture-request-001`, and `fixture_profile`.
- Use only the `default` and `fixture_profile` scopes for profile-isolation cases. Profile names must remain valid Hermes identifiers; current Hermes' `_PROFILE_ID_RE` is `[a-z0-9][a-z0-9_-]{0,63}`.
- Use synthetic text such as `fixture prompt`, `fixture answer`, and `fixture assistant response`. Never copy a real prompt, transcript, tool output, path, email address, or username.
- Use `<fixture-cwd>` or another non-host path marker for workspace metadata. Do not include a real absolute path.
- Tickets, bearer values, cookies, PKCE values, private keys, and other credentials are represented only by placeholders such as `<fixture-ticket>` in documentation. They are never stored as captured values.
- Do not store live origins, DNS names, IPs belonging to a deployment, `Authorization`, `Cookie`, `Set-Cookie`, browser headers, or proxy headers. Authenticated cases express authentication as fixture metadata, not a credential-bearing header.
- Keep JSON unknown/additive fields synthetic and non-sensitive. Unknown-field cases prove tolerance; they are not an excuse to preserve a real server payload.
- Keep arrays in server order. Do not sort sessions, messages, choices, or event frames during fixture generation.

## 4. Wire representation and canonicalization

### HTTP fixtures

Store a request description and response body separately. The request description must assert:

- HTTP method and exact relative path;
- parsed query items, including explicit profile, limit, offset, order, and archived values;
- path-segment encoding for durable IDs;
- whether the request is bodyless or has a JSON body;
- expected bounded response class and status.

For JSON bodies, use UTF-8, LF line endings, deterministic formatting, and no insignificant whitespace in the semantic comparison. Preserve all meaningful string whitespace. Do not treat a response that exceeds its cap as an empty successful response.

The current Hermes transcript route returns `messages` plus `pagination`. A compatibility fixture may exercise the older `data` alias because both iOS `TranscriptEnvelope` and Android `HermesTranscriptResponse` accept it, but the canonical current fixture uses `messages`.

### WebSocket fixtures

Store one ordered JSON-RPC/event text frame per record in a UTF-8 JSONL file, or an equivalent ordered array of raw frame strings. The record's JSON string values are part of the test data:

- `message.delta` values are incremental fragments, not cumulative snapshots;
- a fragment beginning with a space must retain that space;
- `message.complete.text` is the full authoritative replacement;
- `jsonrpc`, `method`, `id`, `params.type`, `params.session_id`, and payload field names are not renamed;
- array order is wire order;
- no frame is silently dropped, duplicated, reparsed, or reserialized by the relay comparison harness.

A JSONL line ending is a fixture-file delimiter, not a WebSocket payload byte. If a test needs to assert outer frame bytes beyond JSON value semantics, store the raw text separately and compare it before parsing. The relay itself must preserve the inner Hermes text frame exactly.

## 5. Cap and boundary policy

These values are copied from the current mobile safety gates and Hermes route validation. They are independent bounds; a message count does not guarantee a response byte size.

| Item | Bound | Source |
|---|---:|---|
| General REST response | 64 KiB | iOS `HermesHTTPClient.maxResponseBytes`; Android `MAX_RESPONSE_BODY_BYTES` / `readBodyTextBounded` |
| Transcript REST response | 1 MiB | iOS `SessionsClient.maxTranscriptResponseBytes`; Android `MAX_TRANSCRIPT_BODY_BYTES` |
| WS-ticket response | 16 KiB | iOS `wsTicketMaxResponseBytes`; Android `MAX_TICKET_RESPONSE_BYTES` |
| One chat WebSocket frame | 36 MiB | iOS `maxFrameBytes`; Android `HERMES_CHAT_MAX_FRAME_BYTES` |
| Session-list page | client default 20; Hermes server maximum 500 | iOS/Android session callers; Hermes `get_profiles_sessions` `limit ... le=500` |
| Transcript page | client initial 100; Hermes explicit maximum 500 | iOS/Android transcript callers; Hermes `get_session_messages` |
| Profile identifier | 64 characters, Hermes identifier grammar | Hermes `profiles._PROFILE_ID_RE`; Android profile bounds |
| Event/runtime ID | 256 characters | iOS `maxEventIDChars`; Android `HERMES_CHAT_MAX_EVENT_ID_CHARS` |
| Event name/status | 256 characters | iOS `maxEventNameChars`; Android `HERMES_CHAT_MAX_EVENT_NAME_CHARS` |
| Small event text/metadata | 4,096 characters | iOS `maxEventTextChars`; Android `HERMES_CHAT_MAX_EVENT_TEXT_CHARS` |
| Message/stream text | 1 MiB | iOS `maxMessageTextChars`; Android `HERMES_CHAT_MAX_MESSAGE_TEXT_CHARS` |
| Tool context | 4,096 characters | iOS `maxEventContextChars`; Android `HERMES_CHAT_MAX_EVENT_CONTEXT_CHARS` |
| One approval choice | 256 characters | iOS `maxEventChoiceChars`; Android `HERMES_CHAT_MAX_EVENT_CHOICE_CHARS` |
| Approval choices | 32 entries | iOS `maxEventChoiceCount`; Android `HERMES_CHAT_MAX_EVENT_CHOICES` |
| Mobile event buffer | 128 events, drop oldest | iOS `maxEventBuffer`/`EventRingBuffer`; Android `MAX_EVENT_BUFFER`/`Channel(DROP_OLDEST)` |
| WS-ticket TTL | 30 seconds, single-use | Hermes `dashboard_auth.ws_tickets.TTL_SECONDS`, `mint_ticket`, `consume_ticket` |

Boundary fixtures must test both the accepted-at-bound and rejected-over-bound cases where the boundary is meaningful. Generate large deterministic padding in the test harness rather than checking in megabytes of opaque filler. Record the intended size and digest in metadata. An oversize response must produce a distinct bounded-read/oversize outcome and must not be reclassified as a valid empty list/transcript.

## 6. Required v1 fixture scenarios

The following scenario families are required before the Relay v1 implementation is enabled. Names are policy names, not claims that files already exist.

### HTTP

1. **`status-minimal-and-additive`** — `GET /api/status`; minimum fields decode, extra synthetic liveness fields are ignored, and no host-local detail is present.
2. **`session-list-default-scope`** — explicit `profile=default`, recent order, archived exclusion, page 20, offset 0; rich row fields decode.
3. **`session-list-profile-isolation`** — the same-looking durable IDs in `default` and `fixture_profile` remain separate scopes; the client never merges them by `session_key` or by title.
4. **`session-list-cap`** — page 500 is accepted by the route policy; 501 is rejected before forwarding. Include `total`, `limit`, and `offset` response fields.
5. **`transcript-latest-tail`** — explicit `profile`, `limit=100`, `offset=0`, and `order=latest`; returned pagination is checked and older-page offset advances from the newest window.
6. **`transcript-compatibility-shapes`** — current `messages` envelope, compatibility `data` envelope, a tool row without `content`/`text`, and optional assistant reasoning fields.
7. **`transcript-id-encoding`** — a synthetic opaque durable ID containing path-significant characters is encoded as one path segment; no path traversal or query injection is possible.
8. **`transcript-cap`** — deterministic responses at the 1 MiB boundary and just over it; the latter is an oversize failure, not `[]`.
9. **`loopback-session-token-boundary`** — protected REST without the host-local session header is rejected; the same request with the header succeeds; fixture metadata records only `authenticated: true` and never the credential.

### WebSocket/JSON-RPC

1. **`ws-ready-and-correlation`** — `gateway.ready` is preserved, request IDs are echoed, and an RPC response is not matched by method or arrival order.
2. **`session-create`** — `close_on_disconnect=false`, explicit profile, optional synthetic cwd, runtime `session_id`, durable `stored_session_id`, and no eager durable row assumption.
3. **`session-resume`** — durable list `id` is sent as `params.session_id`, profile is identical to the list scope, `close_on_disconnect=false`, and result keeps runtime/durable IDs distinct.
4. **`session-resume-inflight`** — `inflight.user`, `inflight.assistant`, and `inflight.streaming` rebuild a streaming placeholder after a lost terminal event.
5. **`prompt-stream`** — `prompt.submit` returns `{status:"streaming"}`, then `message.start`, incremental deltas, and one authoritative `message.complete`.
6. **`delta-leading-whitespace`** — deltas such as `HE`, ` WORLD`, and ` SPACES` append to `HELLO WORLD SPACES`; no trim is allowed.
7. **`complete-statuses`** — `complete`, `interrupted`, and `error` are distinct; `interrupted` is never normalized to `cancelled`.
8. **`reasoning-separation`** — reasoning events remain outside `message.delta`; `reasoning.available` is a replacement snapshot.
9. **`tool-and-status-events`** — bounded `tool.start`, `tool.complete`, `tool.generating`, and `status.update` preserve required fields and ordering.
10. **`cancel`** — `session.interrupt` uses the runtime ID and returns `{status:"interrupted"}`; it is not a session deletion or a background-process kill.
11. **`approval-round-trip`** — ordered choices, request ID, redacted command, `approval.respond` with the advertised choice, current `{resolved:1}` result, and `{resolved:0}` expired result.
12. **`clarify-round-trip`** — request ID, question, choices including `[]`, optional `multi_select`, `clarify.respond` with an answer including `""`, and `status:"expired"` for a late answer.
13. **`malformed-and-unknown`** — parse-error/invalid-version/unknown-method behavior is bounded; unknown additive event types are preserved at the relay boundary and ignored by the mobile projection.
14. **`disconnect-reconcile`** — a close with `close_on_disconnect=false` does not imply `session.close`; reconnect uses durable resume and the transcript tail to reconcile.

### Later authenticated-loopback mode

These scenarios are retained as policy names but do not block the v1 process-token path selected by ADR 0004:

1. **`ticket-bodyless-and-single-use`** — bodyless `POST /api/auth/ws-ticket`, `{ticket, ttl_seconds}`, positive TTL, and no credential persisted in the fixture; the protocol test models first consume success and second consume rejection.
2. **`ticket-cap`** — a response at the 16 KiB ticket cap and one over it; the over-cap response fails before JSON decoding.

## 7. Direct-versus-relay acceptance

Fixtures are used at two boundaries:

- **Direct Hermes oracle:** run the exact official client request against a deterministic local Hermes test double or a disposable loopback instance, then sanitize to the fixture schema.
- **Relay fidelity:** unwrap the local secure-channel test harness and compare the inner Hermes request/response/event sequence against the same fixture.

The relay comparison must prove:

- relative HTTP path, method, query values, JSON fields, and response status are unchanged;
- WebSocket event order and raw text values are unchanged;
- leading whitespace in delta payloads survives;
- no Relay-specific Hermes method or field appears;
- forbidden routes/methods are rejected before any host-side Hermes request is sent;
- no credentials, live origin, or user content is visible in router captures, fixture metadata, or logs.

Do not compare only a deserialized/re-serialized object for the WS fidelity gate. Semantic decoding is useful for client parser tests, but the Relay gate must also retain raw text-frame identity.

## 8. Review and update procedure

When Hermes or either mobile client changes a used route/method/event:

1. update the allow-list in `src/mercury_relay_plugin/method_policy.py` first;
2. identify the exact current source symbol and both client call/parser boundaries;
3. decide MVP, later, or blocked; do not silently widen the allow-list;
4. add or revise a synthetic fixture and its manifest provenance;
5. run the direct and relayed replay checks, including cap and malformed-input cases;
6. run a source-coverage search for every v1 path/method/event and verify the result has no unrepresented v1 call;
7. review the diff for secrets, live hostnames, absolute host paths, and accidental payload logging.

No fixture may be marked canonical merely because it was generated successfully. It is canonical only after source provenance, sanitization, bounds, and direct-versus-relay fidelity have all been reviewed.
