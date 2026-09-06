# Relay image-read contract

`relay.image.read` is an additive plugin-owned read on the existing approved,
admitted Noise/E2EE controller channel. No HTTP proxy, public upload, URL
fetching, or binary side channel is involved. Hermes core is unchanged.

## Discovery

`relay.status` adds `result.capabilities.image_read` when host policy and secure
local file access are available:

```json
{"method":"relay.image.read","max_bytes":2097152,"mime_types":["image/png","image/jpeg","image/gif","image/webp","image/bmp"]}
```

Clients must gate on this entry and serialize image reads to avoid the existing
bounded attachment backpressure (4 MiB default queue). Missing policy helpers or
POSIX descriptor-relative/no-follow APIs hide the entry and fail reads closed.
Windows currently does not advertise this capability.

## Request and response

```json
{"jsonrpc":"2.0","id":"img-1","method":"relay.image.read","params":{"profile":"default","path":"/tmp/example.png"}}
```

Both params are required; no other params are accepted. Profile must currently
exist and pass the installation's normal profile authorizer. Filesystem policy
is installation-scoped, not a new profile filesystem sandbox.

Path is an absolute local filesystem path of at most 4096 UTF-8 bytes, with no
control characters, URL schemes, network share prefix, or `..` components.
Relative paths, `file:` URLs, caller-selected roots and byte limits are rejected.
ID is a nonempty string of at most 128 UTF-8 bytes or a signed 64-bit integer
(not bool). Malformed request envelopes are rejected by transport policy.

```json
{"jsonrpc":"2.0","id":"img-1","result":{"mime_type":"image/png","size":1234,"base64":"<standard padded base64 of exact file bytes>"}}
```

There is no data-URL prefix, truncation, or transcoding. Maximum raw file size is
2,097,152 bytes. PNG/JPEG/GIF/WebP/BMP extensions must agree with the host's image
signature classifier. This is signature validation, not a complete image decode;
clients still need safe image decoders and decoded-dimension/memory limits. SVG
and other active/document formats are excluded.

Host `_managed_files_policy(create_root=False)`, `_canonical_path`, and
`_path_is_under` from `hermes_cli.web_server_files` plus `_is_sensitive_path` and
`_chat_image_extension` from `hermes_cli.web_routers.files` are the fail-closed
adapter seams. No copied sensitive denylist or permissive fallback. Policy is
currently request-independent; an incompatible/request-dependent host policy
fails closed rather than inventing an HTTP identity. An unlocked local host
allows `/tmp`; a locked host cannot escape its managed root. Both input aliases
and resolved targets pass sensitive-path checks. Reads do not create roots.
Canonical directory components are opened using pinned directory descriptors
and `O_NOFOLLOW`; final descriptors are verified as regular files, opened
nonblocking to reject raced FIFOs, and read with a cap-plus-one limit. Concurrent
same-OS writers remain in the host trust boundary; this is not a content snapshot.

Device authorization is rechecked before dispatch and after asynchronous I/O.
Responses are fresh, not retained/replayed, and do not advance the lease cursor.

## Errors

```json
{"jsonrpc":"2.0","id":"img-1","error":{"code":-32000,"message":"image_not_available"}}
```

Stable messages: `invalid_params`, `profile_not_available`, `reads_unavailable`,
`image_not_available` (missing/denied/non-image/nonregular), `response_too_large`,
`device_not_authorized`, plus existing `rate_limited` / `read_failed`. No file
paths or host exception strings appear in errors.

## Byte-budget derivation

Actual framing permits a 16,777,216-byte logical message. Each fragment carries
65,469 payload bytes: 65,519 Noise plaintext minus the 50-byte MR header, then a
16-byte tag for at most 65,535 ciphertext bytes. Fragments are existing canonical
kind-1 frames; no framing version or limit changes are needed.

For this contract's bounded ID, worst-case success JSON overhead is 856 bytes:
128 control bytes escaped to 768 bytes, longest MIME, seven-digit size, and
compact JSON-RPC/result envelope. Base64 is `4 * ceil(raw_bytes / 3)`.

| Budget | Bytes |
|---|---:|
| Selected raw cap | 2,097,152 |
| Base64 at cap | 2,796,204 |
| Worst-case response | 2,797,060 |
| Exact framing-only raw bound (857 overhead at eight-digit size) | 12,582,267 |
| Default attachment-queue raw bound at this overhead | 3,145,086 |

The selected cap requires 43 fragments and leaves headroom in the smaller
4,194,304-byte attachment queue. Multiple buffered images, existing chat traffic,
or custom smaller queue limits can still trigger normal backpressure. There is
no streaming/chunk API, image replay, or unlimited queue.

## Verification

Run `scripts/compat_gate.sh tests/test_image_reads.py` from the repository root using the
existing Hermes interpreter; no install is required. This exercises real host
policy imports and temporary files, profile validation, strict parameters,
capabilities, sensitive names/trees and aliases, symlink swap protection,
regular-file rules, exact cap/oversize behavior, canonical framing, and a real
Noise handshake/admission/read/revocation round trip. The fake inner Hermes
bridge is deliberately never reached for image reads. Run `scripts/compat_gate.sh`
for the full surrounding plugin contract suite. Production deployment and mobile
rendering are separate verification steps owned by the caller.