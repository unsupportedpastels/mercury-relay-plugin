# Mercury Relay plugin for Hermes Agent

An optional, open-source server-side plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent)
that lets the [Mercury](https://github.com/unsupportedpastels/mercury) Android
and iOS apps reach your Hermes host when it has no reachable server origin
(behind NAT, on a laptop, on a home network with no port forwarding).

The plugin opens one outbound connection from your host to a hosted router and
carries the normal Hermes JSON-RPC session contract inside an end-to-end
encrypted channel that terminates on your phone and on this plugin. The router
in the middle is closed source and operated by the Mercury maintainers. **Hermes
session content is forwarded only as ciphertext.** The optional APNs bridge is
separate: the relay also receives push registration metadata and sends generic
notifications (see below). The host plugin, phone apps, and shared protocol test
vectors are open for audit.

## What the router can and cannot see

Inside the encrypted channel (never visible to the router):

- every Hermes request and response, including prompts, transcripts,
  attachments, file reads, and session metadata
- your Hermes credentials, which never leave the host at all; the plugin talks
  to Hermes in-process
- the device identity, host identity, and pairing acknowledgement

Visible to the router, by design:

- a random per-installation route identifier and the connection role
  (`host` or `device`)
- the open/close boundaries of each device connection
- ciphertext record sizes and timing
- the device's routing token, an admission credential for the router that
  grants nothing on the Hermes side
- **only with optional push enabled and a device registered:** the APNs device
  token, sandbox environment, random revocable wake handle, fresh random event
  IDs, host routing JWT, and registration/wake timing. The relay's APNs sender
  and Apple can see the generic notification, never Hermes conversation content

The plugin never exposes a listener. The host connection is outbound only,
reconnects with capped backoff, and treats any router protocol violation as a
reason to drop and reconnect without logging detail.

## How the channel is built

- **Handshake:** `Noise_XK_25519_ChaChaPoly_SHA256` with the prologue
  `mercury-relay/v1\0`. The `XK` pattern means the phone already holds the
  host's static public key before the first packet, so a party in the middle
  cannot substitute its own key. See `src/mercury_relay_plugin/secure_channel.py`.
- **Key delivery:** the host's public key and a one-time pairing capability
  travel inside a QR code you generate on the host and scan with the phone. The
  short fingerprint shown on both sides lets you confirm you paired with your own
  host. See `src/mercury_relay_plugin/pairing_qr.py` and `authorization.py`.
- **Framing:** plaintext Hermes bytes are wrapped in a fixed 50-byte record
  header before encryption, with hard caps on record size, logical message size,
  and fragment count. See `src/mercury_relay_plugin/framing.py` and
  `protocol/schemas/framing-envelope-v1.json`.
- **Method policy:** only an explicit allow-list of Hermes methods is reachable
  over relay. See `src/mercury_relay_plugin/method_policy.py`.
- **Admission:** a paired device must be approved on the host before it can open
  a session. Pending or revoked devices simply see the socket close. See
  `src/mercury_relay_plugin/admission.py`.

## Auditing it yourself

1. **Read the host side.** `relay_client.py` sends the encrypted session stream
   and routing control frames. The optional `push.py` sends bounded HTTPS push
   registration/deletion/generic-wake requests; `session_lease.py` observes live
   controller events and `admission.py` binds push registration to the admitted
   device and authorization epoch. `update_check.py` separately checks release
   metadata. No push request contains a session/profile/tool name or message.
2. **Read the phone side.** The clients live in the Mercury repository:
   `shared/mercury-core/src/commonMain/kotlin/com/unsupportedpastels/mercury/core/relay/`
   (shared protocol, framing, and Noise state), plus the thin Android and iOS
   transports under `app/.../relay/` and `ios/Mercury/MercuryKit/Relay/`.
3. **Check both ends agree.** `protocol/vectors/` holds the canonical handshake,
   transport, and framing vectors. The Mercury repository vendors the same files
   byte for byte and tests against them, so a change to either end shows up as a
   failing test rather than a silent divergence.
4. **Run the tests.**

```bash
python -m pip install -e . pytest pyyaml
python -m pytest -q
```

The suite runs without a Hermes checkout; the in-process Hermes contract tests
skip in that case. To run them too, point `scripts/compat_gate.sh` at a Hermes
source tree. Node.js 18+ is required to execute the desktop behavioral tests;
without Node, those tests and the JavaScript syntax check explicitly skip.

## Optional iOS push notifications

Disabled by default. Set `MERCURY_RELAY_PUSH_ENABLED=1` in the plugin host's
launch environment to opt in at its next normal lifecycle start. This uses the
existing configured `relay_origin`, exact installation route, and host routing
JWT issuer; **no Apple publisher `.p8` key belongs on the Hermes host**. The
relay must separately have its sandbox APNs registry/sender configured.

An admitted encrypted controller sees `capabilities.push_notifications_v1: true`
in `relay.lease.attached` and `relay.status` only when the bridge is configured.
`relay.push.register` accepts exactly `{device_token, environment}` (lowercase
even-length hex, 32–200 characters; `environment: "sandbox"`) and returns
`{registered: true, wake_handle}`. `relay.push.unregister` accepts `{}` and
returns `{registered: false}`. Both are handled inside the plugin, not forwarded
to the official Hermes gateway. Callers cannot choose a device ID or epoch.

A registered device receives generic wakes for assistant `message.complete` and
blocking approval/clarification/secure-input requests observed by its retained
controller, including while attached-but-suspended or detached. Historical
replay, interim/user/tool events, and interrupt sentinels do not wake it. The
relay alert is “Mercury — An update is available. Open Mercury to continue.”
The app must reconnect and retrieve actual state over the encrypted channel.
This does not extend the existing detached lease TTL or keep controllers alive
indefinitely, and it is not a host-wide session monitor.

The host stores only random handles, device/epoch and canonical HTTPS origin /
installation-route bindings, and revocation
cleanup state in private `mercury-relay/push.json`; APNs device tokens are not
persisted there. Revocation immediately fences queued/future wakes and cancels
in-flight HTTP. Deletion failures retain cleanup tombstones, retried after
60 seconds idle and at the next enabled lifecycle start **only when the binding
matches the current origin and installation**. Changed-registry rows are fenced
and persisted inactive before any network work. Their deletion remains blocked
debt: the current routing-token provider is not authority to contact an old
registry. Restoring the exact bound registry with its valid host issuer allows
cleanup, never reactivation. No historical credentials are saved or replayed,
and HTTP redirects are never followed. Unregister and drain cleanup before
changing registry when possible. Already accepted
HTTP/APNs notifications cannot be recalled. The queue is capped at 64 jobs,
registry at 64 rows, dedup at 256 event identities, and each HTTPS operation at
5 seconds. Wakes are best effort (dropped on overload/failure), not an audit log.
Unregister before disabling push if remote registration cleanup is required.

**Migration from v1 push state:** v1 rows did not record their origin or route.
They migrate to inactive v2 tombstones with null bindings; the plugin never
guesses their destination, wakes them, or submits their handles to any registry.
Devices must register again to obtain new bound handles. New registrations work
alongside this debt until the shared 64-row cap is reached (`rate_limited`);
blocked debt is never silently evicted. The owner must reconcile unknown legacy
registrations with the original registry operator using independently verified
destination/authorization information before retiring their local tombstones.
Do not fill in guessed bindings or delete the state file to bypass cleanup.
The bounded state read is 128 KiB to accommodate 64 full v2 records, including
escaped device identifiers; the queue and registry caps are unchanged.

Offline harness (real Noise admission/framing, fake Hermes controller and HTTP
peer; no Apple/Cloudflare connection or credentials):

```bash
scripts/compat_gate.sh tests/test_push.py tests/test_push_lifecycle.py tests/test_push_binding.py
scripts/compat_gate.sh  # full suite, including required Hermes contract tests
```

Use `HERMES_AGENT_ROOT` / `HERMES_PYTHON` to point that gate at a compatible
Hermes checkout/interpreter. Standalone: `uv run pytest -q tests/test_push.py`
(the default suite permits missing-Hermes contract tests to skip).

For an isolated loopback Wrangler gate, reuse `tests/test_push.py` rather than
starting/restarting a shared Hermes process. `admitted_peer(temp_path,
handler=forward)` returns `(service, runtime, admitted, rpc, requests, status,
offer)` after real Noise admission; `rpc` uses encrypted framing, not a direct
bridge call. Its real `PushBridge` uses `https://relay.example` and an injected
`httpx.MockTransport`; only the test HTTP peer redirects the bytes to loopback:

```python
# Inside an async test with a lifecycle-owned httpx.AsyncClient named loopback:
async def forward(request):
    return await loopback.post(
        "http://127.0.0.1:8787" + request.url.path,
        content=request.content,
        headers={"Authorization": request.headers["Authorization"],
                 "Content-Type": "application/json"},
    )
```

Use a temporary `profile_paths` root. The helper generates its test installation
and signing key via `RoutingIssuerStore(service.repository.store).load_or_create()`;
that issuer's `machine_id(offer.installation_id)` and `public_key_b64url` provide
the local Worker's test allowlist/key inputs. Configure those before calling
`rpc("relay.push.register", ...)`. Then `emit_and_drain(admitted, service.push,
event("message.start"), event("message.complete", {"text": "test answer"}))`
exercises the production retained lease reader through authenticated Worker HTTP.
`emit_and_drain` also accepts `event("clarify.request", {"request_id": "test"})`.
Always `await service.close()` and `await runtime.close()` in `finally`. This
transport injection leaves production HTTPS/origin/redirect checks unchanged;
it is test-only and does not validate delivery to Apple or a physical device.

## Install

Requirements: a macOS, Linux, or Windows host running Hermes Agent with the
web dashboard, Python 3.11 to 3.13, and `git` on `PATH` (Hermes clones this
repository with git and does not bundle it; options 1 and 2 below fail with
`git is not installed or not in PATH` without it). The `cryptography` package
ships with Hermes; optional push also requires `httpx==0.28.1`, declared in both
`plugin.yaml` and `pyproject.toml`. Supported Hermes installs already include
`httpx[socks]==0.28.1` as a mandatory dependency. Hermes checks declared Python
**distribution presence** (not version compatibility) and warns with an install
hint; it does **not** auto-install them.
On a stripped/custom environment, restore the declared dependencies in the
interpreter running Hermes (not an unrelated system Python). Missing push
dependencies fail bridge setup closed without disabling the ciphertext connector.
The Noise implementation and QR generator are vendored under
`src/mercury_relay_plugin/_vendor/`; supported Hermes installs need no extra pip step.

On POSIX hosts the plugin keeps its keys and state in `0600` files inside a
`0700` directory and opens them relative to a pinned directory descriptor with
`O_NOFOLLOW`. On Windows those primitives do not exist, so the plugin
re-validates every path component before each open, refuses reparse points
(symlinks and junctions), and relies on the per-user ACL of the Hermes home
under `%LOCALAPPDATA%` for ownership isolation. The encrypted image-read
extension is advertised on POSIX hosts only. See
`src/mercury_relay_plugin/secure_fs.py` for the exact split.

Pick whichever of these fits. All three end with the same thing on disk: a
git checkout at `plugins/mercury-relay` under your Hermes home, listed under
`plugins.enabled` in `config.yaml`. The default home is `~/.hermes` on macOS
and Linux and `%LOCALAPPDATA%\hermes` on Windows, or whatever `HERMES_HOME`
points at.

**Option 1: one click from Hermes Desktop.**

[**Install in Hermes**](https://unsupportedpastels.github.io/mercury-relay-plugin/install.html)

That page opens Hermes Desktop with a confirmation dialog. Nothing is installed
until you confirm. Hermes detects both halves of this repository and installs
the gateway half on whichever gateway is active in Hermes Desktop, local or
remote, and the desktop half on the computer you clicked from. Leave both
checkboxes and the Enable switch on, and read the dialog before closing it:
the two halves install independently, so a failed gateway half shows a red
error in the dialog while the desktop half still reports success. If Hermes
Desktop is not installed on that computer, the page falls back to the command
below.

**Option 2: one command, any platform.** Run this on the machine that runs the
Hermes gateway. It is the same on macOS, Linux, and Windows:

```bash
hermes plugins install unsupportedpastels/mercury-relay-plugin
```

Answer `y` when asked to enable the plugin. Hermes runs its install validation
and supply-chain scan on the checkout before enabling it.

**Option 3: clone it yourself.**

macOS and Linux:

```bash
git clone https://github.com/unsupportedpastels/mercury-relay-plugin "${HERMES_HOME:-$HOME/.hermes}/plugins/mercury-relay"
```

Windows (PowerShell):

```powershell
git clone https://github.com/unsupportedpastels/mercury-relay-plugin "$(if ($env:HERMES_HOME) { $env:HERMES_HOME } else { "$env:LOCALAPPDATA\hermes" })\plugins\mercury-relay"
```

Then enable it in your Hermes `config.yaml`:

```yaml
plugins:
  enabled:
    - mercury-relay
```

### After every install or update: restart the right process

**Finish your running tasks, then fully quit and reopen Hermes Desktop**
(**Cmd+Q** on macOS; **Quit/Exit** elsewhere). This applies to all three install
options above and to updates. Closing the window, reloading the desktop plugin,
or running `hermes gateway restart` does **not** restart Desktop's separate
`hermes serve` child for **"This device"**. Plugin API routes mount at backend
startup; the desktop UI can load before those routes exist.

For a remote connection, restart the API-serving process on that host too.
`hermes gateway restart` restarts the gateway service; if you run `hermes serve`
or `hermes dashboard` separately, restart that process as well.

After installation, open **Mercury Relay** in the Desktop sidebar (enable the
desktop half under **Settings > Plugins** if needed). Its postinstall guidance
is visible even when the backend API is absent. This repository owns that page,
not Hermes' core installation dialog.

If the relay page still shows a 404, check the response:

- `{"detail":"Plugin not found"}` indicates the enablement gate. Confirm
  `mercury-relay` is enabled in the backend's `HERMES_HOME`; run
  `hermes plugins enable mercury-relay` there, then restart the right process.
- `{"detail":"Not Found"}` or the headless fallback
  ``{"error":"Headless backend (hermes serve): web UI disabled — use `hermes dashboard` for the browser UI."}``
  on the plugin API path calls for a backend restart after installation.
  The headless fallback does **not** mean headless backends cannot serve plugin
  APIs: a backend started before installation has not mounted the route yet.
- Other 404s show **relay API unavailable**: installation state is unknown,
  not proof the plugin is missing. Check the active connection, installation,
  enablement, and backend logs if restarting does not resolve it.

The dashboard gains a **Mercury Relay** tab where you create a
one-time pairing QR, compare the fingerprint the phone shows, and approve or
revoke devices. If the phone's camera cannot read the QR (some cameras zoom in
and crop it), use **Copy pairing code** next to the QR and paste the code into
Mercury instead. The code carries the same one-time secret as the QR and
expires with it.

### Relay origin

The plugin dials the hosted Mercury relay by default, so a fresh install needs
no relay configuration at all. To point an installation at a different relay
(your own deployment of the router, for example), set `relay_origin` in the
plugin's public config file, `mercury-relay/config.json` under the gateway's
Hermes home, and restart the gateway:

```json
{"schema_version": 1, "profile_id": "default", "relay_origin": "https://relay.example.net"}
```

The value must be a bare `https` or `wss` origin: scheme and host, optional
port, nothing else. Leave the field out to use the hosted relay.

### Getting the hosted relay to accept this host

The hosted relay only routes for installations the relay operator has
allowlisted. The tab's **Relay access** card shows this installation's
**Relay machine ID** (`MR-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`). Send it to the
operator, using the **Copy** button rather than retyping it. It is a hash over
this installation's relay route and its routing issuer public key: not a
secret, useless for any other installation, and it changes only if the
plugin's private state is wiped (in which case send the new one). The
alphabet is letters plus the digits 2 to 7, so it never contains 0, 1, 8 or 9,
and the last character is a check: the operations console rejects an ID with
a misread character instead of adding one that admits nothing. Once it is
allowlisted, the outbound relay connection is admitted within about a minute.
Until then the roster light reads "awaiting relay access".

### Hermes Desktop

The same repository carries a Hermes Desktop plugin in `desktop/plugin.js`.
Hermes Desktop only loads plugins from the machine it runs on, so:

- If Hermes Desktop runs on the host you just installed on, it finds the
  desktop half automatically at `plugins/mercury-relay/desktop/plugin.js`.
  It ships off by default. Turn it on under **Settings > Plugins** and open
  **Mercury Relay** for the postinstall guidance, then follow the full-quit
  restart step above. A loaded sidebar entry does not prove the API is mounted.
- If Hermes Desktop runs on another machine (a Windows laptop talking to a
  Linux host, for example), install the repository there too: click the
  **Install in Hermes** link above from that laptop, or use
  **Settings > Plugins > Install** with the repository URL. The installer
  detects both halves and sets up the desktop one; the server half is inert
  on a machine that is not running Hermes.

The desktop tab talks to whichever gateway is active in Hermes Desktop and
shows a per-connection light for whether relay is installed and reachable.

## Wire contract extensions

Two optional extensions ride inside the encrypted channel and are documented for
client implementers:

- [`docs/IMAGE_READ.md`](docs/IMAGE_READ.md): bounded, policy-checked image
  reads from the host's managed file root.
- [`docs/FOLDERS.md`](docs/FOLDERS.md): versioned, policy-checked folder
  browsing and idempotent directory creation over the encrypted channel.
- [`docs/LEASE_RECOVERY.md`](docs/LEASE_RECOVERY.md): reattaching a device to
  its retained session after a dropped connection, and lease channels so one
  phone can keep several sessions open at once.

## Updates

The plugin checks the public repo's latest release once on gateway start and
then every six hours (one anonymous `GET` to
`api.github.com/repos/unsupportedpastels/mercury-relay-plugin/releases/latest`;
nothing but a version string is read). The relay page shows the result, and a
pulsing "Relay update" pill appears in the dashboard header and the desktop
status bar while a newer release exists. Set `update_check: false` in the
plugin's public config to turn the timer off; "Check now" still works.

"Update now" never replaces code itself. It runs Hermes' own
`hermes plugins update mercury-relay`, so Hermes' install validation and
supply-chain scan apply, and it only works for git checkouts that are not
pinned. Follow [the full-quit restart steps above](#after-every-install-or-update-restart-the-right-process)
after finishing running tasks to load the new version. From Hermes
Desktop the card shows both halves: "Update gateway plugin" updates the active
gateway's plugin (local or remote), and "Update desktop plugin" asks Hermes
Desktop to re-download this plugin and reload it in place on that computer.
That UI reload does not restart Desktop’s separate backend child.

## Layout

- `plugin.yaml`, `__init__.py`: the Hermes plugin manifest and entry point
- `src/mercury_relay_plugin/`: the plugin
- `dashboard/`, `desktop/`: the owner management UI for the dashboard tab and
  Hermes Desktop; never part of the data path
- `protocol/`: framing schema, canonical vectors, and synthetic Hermes contract
  fixtures shared with the phone apps
- `tests/`: unit tests; `tests/integration/` drives a live plugin with a
  virtual phone

## License

MIT. Vendored dependencies keep their own licenses: `noiseprotocol` (MIT) and
`segno` (BSD), see `src/mercury_relay_plugin/_vendor/`.
