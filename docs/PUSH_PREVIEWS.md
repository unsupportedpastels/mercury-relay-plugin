# Encrypted push previews (host contract)

Mercury Relay push-preview v1 is additive to the existing generic v1 registration and v2 tap-resolution contracts. Generic registrations and wakes are unchanged.

## Availability

The host advertises `capabilities.push_previews` only when all of these are true:

- generic push is enabled with `MERCURY_RELAY_PUSH_ENABLED=1`;
- the configured sender supports preview envelopes (`MERCURY_RELAY_PUSH_PREVIEW_ENABLED=1`);
- public plugin configuration has `push_previews: true`.

The capability is:

```json
{"version":1,"register_method":"relay.push.preview.register","unregister_method":"relay.push.unregister","aead":"CHACHA20-POLY1305","max_plaintext_bytes":1280,"max_title_utf8_bytes":160,"max_body_utf8_bytes":640}
```

Clients keep encrypted previews off by default. An absent or unrecognized structured capability must fall back to generic push.

## Registration

`relay.push.preview.register` is handled only inside the authenticated Relay channel. Its exact params are:

```json
{"device_token":"<lowercase even hex>","environment":"sandbox|production","preview":{"version":1,"key_id":"<16-byte canonical base64url>","key":"<32-byte canonical base64url>","completion":true,"attention":true,"include_title":true,"include_response_excerpt":true}}
```

The host persists the key in private mode-0600 schema-v3 state scoped to installation origin/route, authenticated device, authorization epoch, and key ID. The Worker receives only `preview:{version,key_id}`. A retry of the same `(device, epoch, key_id)` refreshes and returns the same handle. A new registration becomes active before the previous row is fenced and asynchronously unregistered; failed replacement leaves the previous active registration intact.

Same-key-ID requests may update effective preferences while retaining the same
key and environment; a changed key or environment under the same key ID is
rejected. Rotate cryptographic material with a fresh key ID. Revocation fences rows synchronously, clears persisted preview keys and queued material before any network await, cancels an in-flight request, and leaves only bounded unregister debt.

## Wake and encryption

Preview wakes use:

```json
{"wake_handle":"<32-byte canonical base64url>","event_id":"<32-byte canonical base64url>","preview":{"version":1,"alg":"C20P","key_id":"<16-byte canonical base64url>","nonce":"<12-byte canonical base64url>","ciphertext":"<ciphertext-plus-tag canonical base64url>"}}
```

Production generates a fresh random 12-byte nonce for each event. ChaCha20-Poly1305 ciphertext includes its 16-byte tag. The AAD is the concatenation of these UTF-8 strings, each prefixed by an unsigned 32-bit big-endian byte length, in exact order:

1. `mercury.push-preview.v1`
2. `1`
3. `C20P`
4. APNs environment
5. wake handle
6. event ID
7. key ID

The compact plaintext is at most 1280 UTF-8 bytes. `iat`/`exp` are integer seconds with a 120-second lifetime. Completion previews use only live authoritative assistant completion output. Titles are accepted only from the live `session.title` event for that runtime and emitted only with a proven recovery binding. Attention previews contain category-specific fixed text and never include request payload text, commands, questions, filenames, tool arguments, or secret prompts. Existing v2 pending-route resolution remains populated for backwards-safe navigation.

The asynchronous sender caps every serialized Worker request at 3072 bytes, uses fresh host routing credentials, follows no redirects, and never logs registration or preview material.

## Arrival inspection (independent of previews)

`capabilities.push_notification_routes` is `{"version":1,"inspect_method":"relay.push.inspect"}`.
The authenticated Noise method accepts exactly `{wake_handle,event_id}` and returns
`{resolved:false}` or `{resolved:true,durable_session_id,profile}`. The provider-visible
identifiers are random lookup keys, never trusted session routing. Only a correlated
live create/resume response establishes the durable/profile binding.

Inspection is non-consuming and indexed by exact event, separate from the v2 one-shot
tap map. At most 64 event routes are retained in memory for 300 seconds; older events
are not reassigned when a newer session wakes the same device. Expiry, revocation,
registration retirement, failed delivery, and shutdown remove inspection entries.
Authorization checks include current installation binding, active handle, device and
epoch. Unbound events return no route. No Hermes API changes are required.

## Shared fixture

`protocol/vectors/push-preview/corpus.json` freezes the cross-language AAD and ChaCha20-Poly1305 vector. KMP and Swift consumers should copy or consume this exact fixture in their test resources; fixed nonces are fixture-only.
