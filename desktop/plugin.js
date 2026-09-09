/**
 * Mercury Relay — Desktop plugin (UI half of the unified package).
 *
 * Runtime-loaded ESM (no build step): the disk loader rewrites the
 * `@hermes/plugin-sdk` and `react` specifiers to injected shims. It adds a
 * `/mercury-relay` page + sidebar row that reuses the SAME authenticated
 * backend as the dashboard page (`/api/plugins/mercury-relay/*`) through
 * `ctx.rest`, so it works over a remote gateway with no configuration.
 *
 * The page has two parts:
 *   1. A GATEWAY ROSTER: every registered connection with a red/amber/green
 *      light for whether the relay is operational there (installed + running +
 *      phone-reachable). Non-active gateways are probed connection-scoped
 *      through the desktop bridge; if a Desktop build lacks that bridge, the
 *      roster degrades to the active gateway only.
 *   2. The ACTIVE gateway's relay controls: pair (server-rendered QR),
 *      approve pending devices after a fingerprint compare, and revoke.
 *
 * Ships OFF by default; the user enables it in Settings ▸ Plugins.
 */

import {
  Button,
  Codicon,
  host,
  PALETTE_AREA,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  STATUSBAR_AREAS,
  useQuery,
  useValue,
} from '@hermes/plugin-sdk'
import { useCallback, useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

// Small createElement-style helper over the jsx runtime.
function h(type, props) {
  const children = Array.prototype.slice.call(arguments, 2)
  const p = props ? { ...props } : {}
  if (children.length === 1) {
    p.children = children[0]
  } else if (children.length > 1) {
    p.children = children
  }
  return (children.length > 1 ? jsxs : jsx)(type, p)
}

const API_BASE = '/api/plugins/mercury-relay'
// Version of THIS desktop half. Kept in step with the plugin manifest by a
// test; the gateway's plugin reports its own version over /update.
const DESKTOP_PLUGIN_VERSION = '0.2.13'
// The public repo both halves install from; the desktop bridge re-clones it.
const PLUGIN_REPO = 'unsupportedpastels/mercury-relay-plugin'

function versionTuple(text) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(text || '').trim())
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null
}
function versionLess(a, b) {
  const x = versionTuple(a)
  const y = versionTuple(b)
  if (!x || !y) return false
  for (let i = 0; i < 3; i++) {
    if (x[i] !== y[i]) return x[i] < y[i]
  }
  return false
}
function formatChecked(ts) {
  if (!ts) return 'never'
  const age = Math.max(0, Math.floor(Date.now() / 1000 - ts))
  if (age < 60) return 'just now'
  if (age < 3600) return Math.floor(age / 60) + ' min ago'
  return Math.floor(age / 3600) + ' h ago'
}

// A runtime plugin can't import a CSS file (blob import), so inject the small
// layout stylesheet once. Colors lean on the app's theme variables with
// neutral fallbacks so it tracks light/dark.
const STYLE_ID = 'mercury-relay-plugin-styles'
function injectStyles() {
  if (typeof document === 'undefined') return
  // Replace, never skip: a hot-reloaded plugin.js must not keep running
  // against the previous version's stylesheet.
  let style = document.getElementById(STYLE_ID)
  if (!style) {
    style = document.createElement('style')
    style.id = STYLE_ID
    document.head.appendChild(style)
  }
  style.textContent = [
    '.mr-page{max-width:880px;margin:0 auto;padding:24px;display:flex;flex-direction:column;gap:18px}',
    '.mr-card{border:1px solid var(--ui-border,rgba(128,128,128,.25));border-radius:12px;padding:18px;display:flex;flex-direction:column;gap:8px}',
    '.mr-card h2{margin:0;font-size:14px;font-weight:600}',
    '.mr-muted{color:var(--ui-text-tertiary,#8a8a8a);font-size:12.5px;line-height:1.5}',
    '.mr-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}',
    '.mr-spread{justify-content:space-between}',
    '.mr-qr-wrap{display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap}',
    '.mr-qr{background:#fff;padding:12px;border-radius:12px;line-height:0;cursor:zoom-in}',
    '.mr-qr svg{width:320px;height:320px;max-width:100%;display:block}',
    '.mr-qr-overlay{position:fixed;inset:0;z-index:1000;background:rgba(0,0,0,.82);display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px;cursor:zoom-out}',
    '.mr-qr-overlay .mr-qr{padding:24px;border-radius:16px;cursor:zoom-out}',
    '.mr-qr-overlay .mr-qr svg{width:min(80vw,80vh);height:min(80vw,80vh);max-width:none}',
    '.mr-qr-overlay .mr-muted{color:#ddd;font-size:14px}',
    '.mr-fingerprint{font-family:ui-monospace,Menlo,monospace;font-size:16px;letter-spacing:1.5px;font-weight:600;word-break:break-all}',
    '.mr-name{font-size:15px;font-weight:600;margin-bottom:2px}',
    '.mr-update-dot{width:8px;height:8px;border-radius:50%;background:#f2c64d;display:inline-block;margin-right:6px;animation:mr-pulse 1.4s ease-in-out infinite}',
    '@keyframes mr-pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.8)}}',
    '.mr-output{margin:8px 0 0;max-height:160px;overflow:auto;font-size:11px;white-space:pre-wrap}',
    '.mr-statusbar{display:inline-flex;align-items:center;gap:4px;cursor:pointer}',
    '.mr-stack{display:flex;flex-direction:column;gap:18px}',
    '.mr-mono{font-family:ui-monospace,Menlo,monospace;letter-spacing:0.5px}',
    '.mr-device{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;border-top:1px solid var(--ui-border,rgba(128,128,128,.18))}',
    '.mr-pill{font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;padding:2px 8px;border-radius:999px;border:1px solid var(--ui-border,rgba(128,128,128,.3))}',
    '.mr-pill.mr-ok{color:#4ea56a;border-color:#2f6b45}',
    '.mr-dot{display:inline-block;width:9px;height:9px;border-radius:50%;flex:0 0 auto}',
    '.mr-dot.green{background:#3fb96a;box-shadow:0 0 6px rgba(63,185,106,.55)}',
    '.mr-dot.amber{background:#e0a53c}',
    '.mr-dot.red{background:#e05a54}',
    '.mr-dot.grey{background:#8a8a8a}',
    '.mr-banner{border-radius:8px;padding:10px 14px;font-size:12.5px;border:1px solid var(--ui-border,rgba(128,128,128,.3))}',
    '.mr-banner.mr-error{border-color:#7a2f2b;color:#e08a85}',
  ].join('')
}

// -- backend access ----------------------------------------------------------

// Connection-scoped probe of ONE gateway's relay status, through the desktop
// bridge. Returns null when the bridge can't scope by connection.
async function probeGatewayStatus(connectionId, timeoutMs = 4000) {
  const bridge = typeof window !== 'undefined' ? window.hermesDesktop : undefined
  if (!bridge || typeof bridge.api !== 'function') {
    return { supported: false }
  }
  try {
    const status = await bridge.api({
      path: `${API_BASE}/status`,
      method: 'GET',
      connectionId: connectionId,
      timeoutMs: timeoutMs,
    })
    return { supported: true, status: status }
  } catch (error) {
    const message = error && error.message ? String(error.message) : ''
    // A 404 means the gateway is reachable but the relay plugin isn't
    // serving there — distinct from a real connection failure. The body
    // says which of three states the gateway is in (see classify404).
    const kind = classify404(message)
    return { supported: true, error: message || 'unreachable', notFound: kind !== null, notFoundKind: kind }
  }
}

// The bridge folds HTTP status and body into the error message ("404: {...}").
// Known Hermes plugin-route responses:
//   {"detail":"Plugin not found"} — the per-request gate: mercury-relay is
//     not in plugins.enabled (or is in plugins.disabled) for the home that
//     backend reads. The install never completed with enable, or it was
//     toggled off.
//   {"detail":"Not Found"} — plain FastAPI: the name IS enabled but the
//     router was never mounted, because plugin API routes mount once at
//     web-server start. That process predates the install and needs a
//     restart. For "This device" that process is Hermes Desktop's own
//     `hermes serve` child, so `hermes gateway restart` does not touch it.
// The headless web-UI fallback can also catch an unmounted API path; it does
// not imply that `hermes serve` cannot mount plugin APIs. Neither this nor a
// generic 404 proves installation state. Keep unknown 404s non-diagnostic.
// Returns 'not-enabled' | 'restart-needed' | 'api-unavailable' | null.
function classify404(message) {
  const text = String(message || '')
  if (!(/\b404\b/.test(text) || /no such api endpoint/i.test(text))) return null
  if (/plugin not found/i.test(text)) return 'not-enabled'
  if (/"detail"\s*:\s*"Not Found"/.test(text) ||
      /Headless backend \(hermes serve\): web UI disabled/i.test(text)) return 'restart-needed'
  return 'api-unavailable'
}

const NOT_FOUND_TEXT = {
  'not-enabled': 'relay installed but not enabled here',
  'restart-needed': 'relay API restart needed',
  'api-unavailable': 'relay API unavailable',
}

function statusOf(result) {
  // green = installed + runtime ready + outbound host socket live (a phone can
  // reach this box now); amber = reachable but relay not fully serving; red =
  // unreachable / auth needed; grey = couldn't determine.
  if (!result) return { color: 'grey', text: 'unknown' }
  if (result.notFound) return { color: 'amber', text: NOT_FOUND_TEXT[result.notFoundKind] || NOT_FOUND_TEXT['api-unavailable'] }
  if (result.error) return { color: 'red', text: 'unreachable' }
  const s = result.status
  if (!s) return { color: 'grey', text: 'unknown' }
  if (s.runtime === 'ready' && s.relay_connected) return { color: 'green', text: 'operational' }
  if (s.runtime === 'ready' && s.relay_origin_configured && s.relay_refusal === 'unauthorized') {
    return { color: 'amber', text: 'awaiting relay access' }
  }
  if (s.runtime === 'ready' && s.relay_origin_configured) return { color: 'amber', text: 'host offline' }
  if (s.runtime === 'ready') return { color: 'amber', text: 'no relay origin' }
  return { color: 'amber', text: 'runtime not ready' }
}

// -- gateway roster ----------------------------------------------------------

function GatewayRoster(props) {
  const activeConnectionId = props.activeConnectionId
  const { data, isLoading } = useQuery({
    queryKey: ['mercury-relay', 'roster'],
    refetchInterval: 8000,
    queryFn: async () => {
      let connections = []
      try {
        connections = await host.connections()
      } catch (e) {
        return { unsupported: true, rows: [] }
      }
      const rows = await Promise.all(
        connections.map(async (conn) => {
          if (conn.kind === 'ssh') {
            return { conn, color: 'grey', text: 'ssh (connect on demand)' }
          }
          const result = await probeGatewayStatus(conn.id)
          if (result.supported === false) {
            return { conn, color: 'grey', text: 'select to check' }
          }
          const t = statusOf(result)
          return { conn, color: t.color, text: t.text }
        }),
      )
      return { unsupported: false, rows }
    },
  })

  if (isLoading) {
    return h('div', { className: 'mr-card' }, h('div', { className: 'mr-muted' }, 'Loading gateways…'))
  }
  const rows = (data && data.rows) || []

  return h(
    'div',
    { className: 'mr-card' },
    h('h2', null, 'Relay hosts'),
    h('div', { className: 'mr-muted' },
      'Every gateway you have connected, and whether a phone can reach its relay right now.'),
    rows.length === 0
      ? h('div', { className: 'mr-muted', style: { marginTop: '10px' } }, 'No gateways connected.')
      : rows.map((row) =>
          h(
            'div',
            { className: 'mr-device', key: row.conn.id },
            h('div', { className: 'mr-row', style: { gap: '10px' } },
              h('span', { className: 'mr-dot ' + row.color, title: row.text }),
              h('div', null,
                h('div', { style: { fontWeight: 600 } },
                  row.conn.label || row.conn.url || row.conn.id,
                  row.conn.id === activeConnectionId
                    ? h('span', { className: 'mr-pill mr-ok', style: { marginLeft: '8px' } }, 'active')
                    : null),
                h('div', { className: 'mr-muted' }, row.text + (row.conn.url ? ' · ' + row.conn.url : '')))),
            row.conn.id === activeConnectionId
              ? null
              : h(Button,
                  { variant: 'ghost', size: 'sm', onClick: () => activateConnection(row.conn.id) },
                  'Switch'),
          ),
        ),
  )
}

async function activateConnection(connectionId) {
  const bridge = typeof window !== 'undefined' ? window.hermesDesktop : undefined
  if (bridge && bridge.connections && typeof bridge.connections.setPrimary === 'function') {
    try {
      await bridge.connections.setPrimary(connectionId)
    } catch (e) {
      // A failed switch leaves the current connection active; the roster
      // re-polls and reflects reality either way.
    }
  }
}

// Shared, API-independent postinstall help: inline in the missing-API card,
// otherwise one compact banner above the controls. Never restart active work.
function InstallRestartGuidance() {
  return h('div', { className: 'mr-muted' },
    h('strong', null, 'After installing or updating: '),
    'finish your running tasks, then fully quit and reopen Hermes Desktop ' +
      '(Cmd+Q on macOS; Quit/Exit elsewhere). Closing the window, reloading the desktop plugin, ' +
      'or `hermes gateway restart` does not restart Desktop’s separate `hermes serve` child. ' +
      'Plugin API routes mount at backend startup. For a remote connection, restart the ' +
      'API-serving process on that host too; `hermes gateway restart` only restarts the gateway service.')
}

// Shown in place of the Pair/Devices cards when the active gateway has no
// serving relay backend. Reads the 404 body to identify known disabled/restart
// states, without treating every 404 as an absent install.
function MissingBackendCard(props) {
  const message = props.error && props.error.message ? String(props.error.message) : String(props.error || '')
  const kind = classify404(message)
  let title = 'Relay not available on this gateway'
  let body =
    'The relay API could not be reached; installation state is unknown. Check the active ' +
    'connection and confirm Mercury Relay is installed and enabled in that backend’s HERMES_HOME.'
  if (kind === 'not-enabled') {
    title = 'Relay plugin is installed here but not enabled'
    body =
      'This gateway has the plugin on disk but mercury-relay is not in plugins.enabled. ' +
      'Run `hermes plugins enable mercury-relay` on that machine (with the same HERMES_HOME ' +
      'the gateway uses), or toggle it on under Settings > Plugins, then restart the gateway.'
  } else if (kind === 'restart-needed') {
    title = 'Relay API restart needed'
    body =
      'The relay route is not mounted in this running backend. After an install or update, ' +
      'restart the API-serving process to load it. A headless web-UI fallback on this API ' +
      'path does not mean headless backends cannot serve plugin APIs.'
  } else if (kind === 'api-unavailable') {
    title = 'Relay API unavailable on this gateway'
  }
  return h(
    'div',
    { className: 'mr-card' },
    h('h2', null, title),
    h('div', { className: 'mr-muted' }, body),
    h(InstallRestartGuidance),
  )
}

// -- active-gateway relay panel ---------------------------------------------

function ActiveRelayPanel(props) {
  // All panel state and caches are scoped to one gateway connection: the
  // page remounts this component (React key) when the active connection
  // changes, and the query keys carry the connection id so gateway A's
  // status/devices can never render while gateway B is active (BR-06).
  const [offer, setOffer] = useState(null)
  const [copied, setCopied] = useState(null)
  const [enlarged, setEnlarged] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)

  const status = useQuery({
    queryKey: ['mercury-relay', props.connectionId || null, 'status'],
    refetchInterval: 4000,
    queryFn: () => props.rest('/status'),
  })
  const devicesQ = useQuery({
    queryKey: ['mercury-relay', props.connectionId || null, 'devices'],
    refetchInterval: 4000,
    queryFn: () => props.rest('/devices'),
  })

  const updateQ = useQuery({
    queryKey: ['mercury-relay', props.connectionId || null, 'update'],
    refetchInterval: 60000,
    queryFn: () => props.rest('/update'),
  })
  const [updateBusy, setUpdateBusy] = useState(false)
  const [updateResult, setUpdateResult] = useState(null)

  const refresh = useCallback(() => {
    status.refetch()
    devicesQ.refetch()
    updateQ.refetch()
  }, [status, devicesQ, updateQ])

  const checkUpdates = useCallback(() => {
    setUpdateBusy(true)
    props
      .rest('/update/check', { method: 'POST', body: {} })
      .then(() => updateQ.refetch())
      .catch((e) => setErr(e && e.message ? e.message : 'failed'))
      .finally(() => setUpdateBusy(false))
  }, [props, updateQ])

  // Desktop half: Hermes Desktop's own installer re-clones the repo and
  // replaces this plugin's folder; the runtime loader hot-reloads plugin.js.
  const [desktopBusy, setDesktopBusy] = useState(false)
  const [desktopResult, setDesktopResult] = useState(null)
  const updateDesktop = useCallback(async () => {
    const bridge = typeof window !== 'undefined' ? window.hermesDesktop : undefined
    const installFn = bridge && bridge.installDesktopPlugin
    if (!installFn) {
      setDesktopResult({ ok: false, error: 'This Hermes Desktop build cannot reinstall plugins from a page. Use Settings ▸ Plugins.' })
      return
    }
    if (
      typeof window !== 'undefined' &&
      !window.confirm('Update the Mercury Relay desktop plugin on this computer now? Hermes Desktop will re-download it and reload it in place.')
    ) {
      return
    }
    setDesktopBusy(true)
    setDesktopResult(null)
    try {
      const r = await installFn({ identifier: PLUGIN_REPO, force: true })
      if (r && r.ok) {
        setDesktopResult({ ok: true })
        // The runtime loader swaps the plugin module when plugin.js changes,
        // but this mounted page is still the old component. Leave the route
        // and come back so the new version renders.
        setTimeout(() => {
          host.navigate('/')
          setTimeout(() => host.navigate('/mercury-relay'), 400)
        }, 1500)
      } else {
        setDesktopResult({ ok: false, error: (r && r.error) || 'failed' })
      }
    } catch (e) {
      setDesktopResult({ ok: false, error: e && e.message ? e.message : 'failed' })
    } finally {
      setDesktopBusy(false)
    }
  }, [])

  const applyUpdate = useCallback(() => {
    if (
      typeof window !== 'undefined' &&
      !window.confirm(
        "Update the Mercury Relay plugin on this gateway now? Hermes will pull the latest release; the gateway must be restarted afterwards.",
      )
    ) {
      return
    }
    setUpdateBusy(true)
    setUpdateResult(null)
    props
      .rest('/update/apply', { method: 'POST', body: {} })
      .then((r) => {
        setUpdateResult(r)
        refresh()
      })
      .catch((e) => setErr(e && e.message ? e.message : 'failed'))
      .finally(() => setUpdateBusy(false))
  }, [props, refresh])

  const createOffer = useCallback(() => {
    setBusy(true)
    setErr(null)
    props
      .rest('/pairing-offers', { method: 'POST', body: {} })
      .then((o) => { setCopied(null); setEnlarged(false); setOffer(o) })
      .catch((e) => setErr(e && e.message ? e.message : 'failed'))
      .finally(() => setBusy(false))
  }, [props])

  const approve = useCallback(
    (device) => {
      if (
        typeof window !== 'undefined' &&
        !window.confirm(
          'Approve this device?\n\nConfirm the fingerprint matches the one on the phone:\n\n' +
            device.fingerprint,
        )
      ) {
        return
      }
      props
        .rest('/devices/' + encodeURIComponent(device.device_id) + '/approve', {
          method: 'POST',
          body: { confirmed_fingerprint: device.fingerprint },
        })
        .then(refresh)
        .catch((e) => setErr(e && e.message ? e.message : 'failed'))
    },
    [props, refresh],
  )

  const rename = useCallback(
    (device) => {
      if (typeof window === 'undefined') return
      const next = window.prompt(
        "Nickname for this device (leave empty to use the phone's own name):",
        device.label || '',
      )
      if (next === null) return
      props
        .rest('/devices/' + encodeURIComponent(device.device_id) + '/label', {
          method: 'POST',
          body: { label: next.trim().slice(0, 64) },
        })
        .then(refresh)
        .catch((e) => setErr(e && e.message ? e.message : 'failed'))
    },
    [props, refresh],
  )

  const deviceTitle = (d) => d.display_name || d.label || d.device_name || d.fingerprint

  const act = useCallback(
    (device, verb) => {
      props
        .rest('/devices/' + encodeURIComponent(device.device_id) + '/' + verb, {
          method: 'POST',
          body: {},
        })
        .then(refresh)
        .catch((e) => setErr(e && e.message ? e.message : 'failed'))
    },
    [props, refresh],
  )

  const backendMissing = status.isError
  const s = status.data
  const devices = (devicesQ.data && devicesQ.data.devices) || []
  const pending = devices.filter((d) => d.status === 'pending')
  const authorized = devices.filter((d) => d.status === 'authorized')

  if (backendMissing) {
    return h(MissingBackendCard, { error: status.error })
  }

  return h(
    'div',
    { className: 'mr-stack', style: { display: 'flex', flexDirection: 'column', gap: '18px' } },
    h('div', { className: 'mr-banner' }, h(InstallRestartGuidance)),
    err ? h('div', { className: 'mr-banner mr-error' }, 'Error: ' + err) : null,
    s && s.relay_origin_configured === false
      ? h('div', { className: 'mr-banner' },
          'No relay origin configured on this gateway — pairing works, but the phone ' +
            'cannot connect until the hosted relay origin is set.')
      : null,

    // The relay answered the last upgrade with 401/403: reachable, but this
    // machine is not on its allowlist yet. Say so instead of "host offline".
    s && s.relay_refusal === 'unauthorized' && !s.relay_connected
      ? h('div', { className: 'mr-banner' },
          'The relay is reachable but refused this gateway: its machine ID is not ' +
            'allowlisted yet. Send the ID below to the relay operator; the connection ' +
            'is admitted within about a minute of being added.')
      : null,

    // relay access: the machine ID is a hash over this gateway's relay route
    // and its routing issuer public key. Not a secret; it admits only this
    // gateway once the relay operator allowlists it in the operations console.
    // The last character is a check so a misread ID is rejected on paste.
    s && s.relay_machine_id
      ? h('div', { className: 'mr-card' },
          h('div', { className: 'mr-row mr-spread' },
            h('div', null,
              h('h2', null, 'Relay access'),
              h('div', { className: 'mr-muted' },
                'Send this machine ID to the relay operator to allow this gateway to ' +
                  'connect to the hosted relay. Use Copy: the ID has no 0, 1, 8 or 9, and ' +
                  'its last character is a check that catches a misread letter.'),
              h('div', { className: 'mr-fingerprint', style: { marginTop: '8px' } },
                s.relay_machine_id)),
            h(Button, {
              variant: 'ghost',
              size: 'sm',
              onClick: () => { copyText(s.relay_machine_id) },
            }, 'Copy')))
      : null,

    // pairing
    h(
      'div',
      { className: 'mr-card' },
      h('div', { className: 'mr-row mr-spread' },
        h('div', null,
          h('h2', null, 'Pair a phone'),
          h('div', { className: 'mr-muted' },
            'Generate a one-time QR, scan it in Mercury, then approve after the ' +
              'fingerprints match.')),
        h(Button, { onClick: createOffer, disabled: busy },
          busy ? 'Generating…' : offer ? 'New QR' : 'Generate QR')),
      offer
        ? h('div', { className: 'mr-qr-wrap', style: { marginTop: '16px' } },
            // Drawn large by default and click-to-enlarge: a bigger target
            // scans from further away, so phone cameras do not have to zoom
            // in on a dense code (and overshoot it) to read it.
            h(QrSvg, { svg: offer.qr_svg, onClick: () => setEnlarged(true), title: 'Click to enlarge' }),
            enlarged
              ? h('div', { className: 'mr-qr-overlay', onClick: () => setEnlarged(false) },
                  h(QrSvg, { svg: offer.qr_svg }),
                  h('div', { className: 'mr-muted' }, 'Scan with Mercury. Click anywhere to close.'))
              : null,
            h('div', { style: { flex: '1', minWidth: '200px' } },
              h('div', { className: 'mr-muted' }, 'Offer'),
              h('div', { className: 'mr-fingerprint' }, offer.offer_id),
              // Camera trouble (auto-zoom cropping the code, no camera at
              // all): the same payload the QR encodes can be copied and
              // pasted into Mercury. It is copied, never rendered as text.
              h('div', { className: 'mr-row', style: { marginTop: '10px' } },
                h(Button, {
                  variant: 'ghost',
                  size: 'sm',
                  disabled: !offer.pairing_payload,
                  onClick: () => {
                    copyText(offer.pairing_payload).then((ok) => {
                      setCopied(ok ? 'copied' : 'failed')
                      setTimeout(() => setCopied(null), 2000)
                    })
                  },
                }, copied === 'copied' ? 'Copied' : 'Copy pairing code'),
                copied === 'failed'
                  ? h('span', { className: 'mr-muted' }, 'Clipboard unavailable')
                  : null),
              h('div', { className: 'mr-muted', style: { marginTop: '10px' } },
                'This QR contains the one-time pairing secret. Scan it, or copy the ' +
                  'pairing code and paste it into Mercury if the camera cannot read ' +
                  'the QR. It is shown once and never stored or displayed as text.')))
        : null,
    ),

    // pending
    pending.length > 0
      ? h('div', { className: 'mr-card' },
          h('h2', null, 'Waiting for approval'),
          h('div', { className: 'mr-muted' }, 'Confirm each fingerprint matches the phone.'),
          pending.map((d) =>
            h('div', { className: 'mr-device', key: d.device_id },
              h('div', null,
                h('div', { className: 'mr-name' }, deviceTitle(d)),
                h('div', { className: 'mr-fingerprint' }, d.fingerprint),
                h('div', { className: 'mr-muted' }, 'pending')),
              h('div', { className: 'mr-row' },
                h(Button, { size: 'sm', onClick: () => approve(d) }, 'Approve'),
                h(Button, { variant: 'ghost', size: 'sm', onClick: () => act(d, 'deny') }, 'Deny')))))
      : null,

    // devices
    h('div', { className: 'mr-card' },
      h('h2', null, 'Devices'),
      authorized.length === 0
        ? h('div', { className: 'mr-muted' }, 'No authorized devices.')
        : authorized.map((d) =>
            h('div', { className: 'mr-device', key: d.device_id },
              h('div', null,
                h('div', { className: 'mr-name' }, deviceTitle(d)),
                h('div', { className: 'mr-muted mr-mono' },
                  (d.label && d.device_name && d.label !== d.device_name ? d.device_name + ' · ' : '') + d.fingerprint),
                h('span', { className: 'mr-pill mr-ok' }, 'authorized')),
              h('div', { className: 'mr-row' },
                h(Button, { variant: 'ghost', size: 'sm', onClick: () => rename(d) }, 'Rename'),
                h(Button, { variant: 'ghost', size: 'sm', onClick: () => act(d, 'revoke') }, 'Revoke'))))),

    // updates last: the gateway's plugin (this host, or the remote gateway the
    // desktop is pointed at) plus this desktop half.
    h(UpdatesCard, {
      update: updateQ.data || null,
      busy: updateBusy,
      result: updateResult,
      onCheck: checkUpdates,
      onApply: applyUpdate,
      desktopBusy: desktopBusy,
      desktopResult: desktopResult,
      onUpdateDesktop: updateDesktop,
    }),
  )
}

function UpdatesCard(props) {
  const u = props.update
  if (!u) return null
  const canApply = u.install && u.install.kind === 'git'
  const desktopBehind = u.latest && versionLess(DESKTOP_PLUGIN_VERSION, u.latest)
  return h('div', { className: 'mr-card' },
    h('div', { className: 'mr-row mr-spread' },
      h('div', null,
        h('h2', null, 'Updates'),
        h('div', { className: 'mr-muted' },
          'Gateway plugin ' + u.installed +
            (u.latest ? ' · latest ' + u.latest : '') +
            ' · checked ' + formatChecked(u.checked_at) +
            (u.enabled ? ' · checks every 6 h' : ' · automatic checks off') +
            (u.error ? ' · last check failed' : '')),
        h('div', { className: 'mr-muted' }, 'Desktop plugin ' + DESKTOP_PLUGIN_VERSION)),
      h('div', { className: 'mr-row' },
        h(Button, { size: 'sm', onClick: props.onCheck, disabled: props.busy }, 'Check now'),
        u.available
          ? h(Button, { size: 'sm', onClick: props.onApply, disabled: props.busy || !canApply },
              props.busy ? 'Updating…' : 'Update gateway plugin')
          : null,
        desktopBehind
          ? h(Button, { size: 'sm', onClick: props.onUpdateDesktop, disabled: props.desktopBusy },
              props.desktopBusy ? 'Updating…' : 'Update desktop plugin')
          : null)),
    u.available
      ? h('div', { className: 'mr-banner' },
          h('span', { className: 'mr-update-dot' }),
          'Mercury Relay ' + u.latest + ' is available on this gateway. Update runs ' +
            u.update_command + ' there through Hermes\' plugin manager; restart that gateway afterwards.')
      : null,
    desktopBehind
      ? h('div', { className: 'mr-banner' },
          h('span', { className: 'mr-update-dot' }),
          'This desktop plugin is ' + DESKTOP_PLUGIN_VERSION + '; ' + u.latest +
            ' is available. Update desktop plugin re-downloads it on this computer and reloads it in place.')
      : null,
    props.desktopResult
      ? h('div', { className: props.desktopResult.ok ? 'mr-banner' : 'mr-banner mr-error' },
          props.desktopResult.ok
            ? 'Desktop plugin updated; reopening the page on the new version…'
            : 'Desktop plugin update failed: ' + props.desktopResult.error)
      : null,
    props.result
      ? h('div', { className: props.result.ok ? 'mr-banner' : 'mr-banner mr-error' },
          props.result.ok
            ? 'Updated. Restart that gateway to load the new version.'
            : 'Update failed: ' + (props.result.reason || 'unknown') + '.',
          props.result.output ? h('pre', { className: 'mr-output' }, props.result.output) : null)
      : null,
  )
}

/** Pulsing statusbar item while the active gateway (or this desktop half) is behind. */
function UpdateStatusbarItem(props) {
  const activeConnectionId = useValue(host.state.connectionId)
  const updateQ = useQuery({
    queryKey: ['mercury-relay', activeConnectionId || null, 'update'],
    refetchInterval: 60000,
    queryFn: () => props.rest('/update'),
  })
  const u = updateQ.data
  if (!u) return null
  const behind = u.available || (u.latest && versionLess(DESKTOP_PLUGIN_VERSION, u.latest))
  if (!behind) return null
  return h('span', {
    className: 'mr-statusbar',
    title: 'Mercury Relay ' + u.latest + ' is available',
    onClick: () => host.navigate('/mercury-relay'),
  }, h('span', { className: 'mr-update-dot' }), 'Relay update ' + u.latest)
}

function QrSvg(props) {
  // The SVG is generated server-side and contains no script; render inline.
  return h('div', {
    className: 'mr-qr',
    title: props.title,
    onClick: props.onClick,
    dangerouslySetInnerHTML: { __html: props.svg || '' },
  })
}

// Copy text to the clipboard. The async Clipboard API needs a secure context
// and a user gesture; fall back to a transient textarea + execCommand for
// the rare shell where it is unavailable. Resolves true when a copy happened.
function copyText(text) {
  if (typeof text !== 'string' || !text) return Promise.resolve(false)
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text).then(() => true, () => copyTextLegacy(text))
  }
  return Promise.resolve(copyTextLegacy(text))
}

function copyTextLegacy(text) {
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand && document.execCommand('copy')
    document.body.removeChild(ta)
    return Boolean(ok)
  } catch (e) {
    return false
  }
}

// -- page --------------------------------------------------------------------

function MercuryRelayPage(props) {
  const activeConnectionId = useValue(host.state.connectionId)
  return h(
    'div',
    { className: 'mr-page' },
    h('div', { className: 'mr-row', style: { gap: '8px' } },
      h(Codicon, { name: 'broadcast' }),
      h('h1', { style: { fontSize: '18px', fontWeight: 600, margin: 0 } }, 'Mercury Relay')),
    h(GatewayRoster, { activeConnectionId: activeConnectionId }),
    h(ActiveRelayPanel, {
      rest: props.rest,
      connectionId: activeConnectionId,
      // Remount on switch: clears the one-time QR offer and any error so no
      // pairing material from the previous gateway stays visible.
      key: activeConnectionId || 'no-connection',
    }),
  )
}

// -- registration ------------------------------------------------------------

export default {
  id: 'mercury-relay',
  name: 'Mercury Relay',
  description: 'Pair phones and manage the encrypted Relay transport across your gateways.',
  defaultEnabled: false,
  register(ctx) {
    injectStyles()
    const rest = (path, opts) => ctx.rest(path, opts || {})
    ctx.registerMany([
      {
        id: 'page',
        area: ROUTES_AREA,
        data: { path: '/mercury-relay' },
        render: () => h(MercuryRelayPage, { rest: rest }),
      },
      {
        id: 'nav',
        area: SIDEBAR_NAV_AREA,
        order: 55,
        data: { codicon: 'broadcast', label: 'Mercury Relay', path: '/mercury-relay' },
      },
      {
        id: 'update-badge',
        area: STATUSBAR_AREAS.right,
        data: {
          id: 'mercury-relay.update',
          render: () => h(UpdateStatusbarItem, { rest: rest }),
        },
      },
      {
        id: 'open',
        area: PALETTE_AREA,
        data: {
          id: 'mercury-relay.open',
          label: 'Mercury Relay: Open',
          keywords: ['mercury', 'relay', 'pair', 'phone', 'qr'],
          run: () => host.navigate('/mercury-relay'),
        },
      },
    ])
  },
}
