# Mercury Relay plugin for Hermes Agent

An optional, open-source server-side plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent)
that lets the [Mercury](https://github.com/unsupportedpastels/mercury) Android
and iOS apps reach your Hermes host when it has no reachable server origin
(behind NAT, on a laptop, on a home network with no port forwarding).

The plugin opens one outbound connection from your host to a hosted router and
carries the normal Hermes JSON-RPC session contract inside an end-to-end
encrypted channel that terminates on your phone and on this plugin. The router
in the middle is closed source and operated by the Mercury maintainers. **It
only ever forwards ciphertext.** Everything needed to check that claim is open:
this plugin, the phone apps, and the protocol test vectors both ends share.

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

1. **Read the host side.** The files above are the whole trust boundary. The
   only module that writes to the network is `relay_client.py`; everything it
   sends is either Noise ciphertext or one of two tiny control frames.
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
source tree.

## Install

Requirements: a macOS, Linux, or Windows host running Hermes Agent with the
web dashboard, Python 3.11 to 3.13, and `git` on `PATH` (Hermes clones this
repository with git and does not bundle it; options 1 and 2 below fail with
`git is not installed or not in PATH` without it). The `cryptography` package
ships with Hermes. The Noise implementation and the QR generator are vendored under
`src/mercury_relay_plugin/_vendor/` so there is no pip step on the host.

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

Whichever option you used, restart the gateway process, because plugin API
routes load once at startup. For a gateway you run yourself that is
`hermes gateway restart`. For the **"This device"** gateway inside Hermes
Desktop, quit and reopen Hermes Desktop: that gateway is a child process the
app runs itself, and `hermes gateway restart` does not reach it.

If the relay page still shows a 404 afterwards, the body tells you which
state the gateway is in. `{"detail":"Plugin not found"}` means `mercury-relay`
is not in `plugins.enabled` for the home that gateway reads; run
`hermes plugins enable mercury-relay` there with the same `HERMES_HOME` and
restart again. `{"detail":"Not Found"}` means it is enabled but the process
has not been restarted since the install. The desktop tab's roster shows the
same distinction as "installed but not enabled", "installed, restart needed",
or "not installed".

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
  It ships off by default. Quit and reopen Hermes Desktop first (the restart
  step above), then turn it on under **Settings > Plugins**: a half switched
  on before that restart shows its sidebar entry but a blank page until the
  app restarts.
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
pinned. Restart the gateway afterwards to load the new version (quit and
reopen Hermes Desktop when the gateway is its "This device" one). From Hermes
Desktop the card shows both halves: "Update gateway plugin" updates the active
gateway's plugin (local or remote), and "Update desktop plugin" asks Hermes
Desktop to re-download this plugin and reload it in place on that computer.

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
