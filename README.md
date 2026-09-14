# Mercury Relay plugin for Hermes Agent

An optional, open-source server-side plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent)
that lets the [Mercury](https://github.com/unsupportedpastels/mercury) Android
and iOS apps reach your Hermes host when it has no reachable server origin
(behind NAT, on a laptop, on a home network with no port forwarding).

The plugin opens one outbound connection from your host to a hosted router and
carries the normal Hermes JSON-RPC session contract inside an end-to-end
encrypted channel that terminates on your phone and on this plugin. The router
in the middle is closed source and operated by the Mercury maintainers. **Hermes
session content is forwarded only as ciphertext.** The host plugin, phone apps,
and shared protocol test vectors are open for audit.

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

## Install

Requires Hermes Agent with the web dashboard and `git` on `PATH`.

[**Install in Hermes**](https://unsupportedpastels.github.io/mercury-relay-plugin/install.html)

Or run this on the machine running the Hermes gateway:

```bash
hermes plugins install unsupportedpastels/mercury-relay-plugin
```

Finish running tasks, then fully quit and reopen Hermes Desktop (`Cmd+Q` on
macOS; `Quit/Exit` elsewhere). Closing the window, reloading the desktop plugin,
or running `hermes gateway restart` alone does not restart the `hermes serve`
process for **"This device"**. If the page reports **API unavailable**, restart
that Hermes process.

Open **Mercury Relay** from the Desktop sidebar to create a pairing QR, approve
devices, and revoke access.

Send the **Mercury Relay ID** shown in the dashboard to the Relay operator so this
host can be allowed to connect.

## Updates

Use Hermes' normal plugin update command when a new release is available:

```bash
hermes plugins update mercury-relay
```

## License

MIT. Vendored dependencies keep their own licenses: `noiseprotocol` (MIT) and
`segno` (BSD), see `src/mercury_relay_plugin/_vendor/`.
