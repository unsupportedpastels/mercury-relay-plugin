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

// A runtime plugin can't import a CSS file (blob import), so inject the small
// layout stylesheet once. Colors lean on the app's theme variables with
// neutral fallbacks so it tracks light/dark.
const STYLE_ID = 'mercury-relay-plugin-styles'
function injectStyles() {
  if (typeof document === 'undefined' || document.getElementById(STYLE_ID)) return
  const style = document.createElement('style')
  style.id = STYLE_ID
  style.textContent = [
    '.mr-page{max-width:880px;margin:0 auto;padding:24px;display:flex;flex-direction:column;gap:18px}',
    '.mr-card{border:1px solid var(--ui-border,rgba(128,128,128,.25));border-radius:12px;padding:18px;display:flex;flex-direction:column;gap:8px}',
    '.mr-card h2{margin:0;font-size:14px;font-weight:600}',
    '.mr-muted{color:var(--ui-text-tertiary,#8a8a8a);font-size:12.5px;line-height:1.5}',
    '.mr-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}',
    '.mr-spread{justify-content:space-between}',
    '.mr-qr-wrap{display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap}',
    '.mr-qr{background:#fff;padding:12px;border-radius:12px;line-height:0}',
    '.mr-qr svg{width:200px;height:200px;display:block}',
    '.mr-fingerprint{font-family:ui-monospace,Menlo,monospace;font-size:16px;letter-spacing:1.5px;font-weight:600;word-break:break-all}',
    '.mr-name{font-size:15px;font-weight:600;margin-bottom:2px}',
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
  document.head.appendChild(style)
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
    // installed/enabled there — distinct from a real connection failure.
    const notFound = /\b404\b/.test(message) || /no such api endpoint/i.test(message)
    return { supported: true, error: message || 'unreachable', notFound: notFound }
  }
}

function statusOf(result) {
  // green = installed + runtime ready + outbound host socket live (a phone can
  // reach this box now); amber = reachable but relay not fully serving; red =
  // unreachable / auth needed; grey = couldn't determine.
  if (!result) return { color: 'grey', text: 'unknown' }
  if (result.notFound) return { color: 'amber', text: 'relay not installed here' }
  if (result.error) return { color: 'red', text: 'unreachable' }
  const s = result.status
  if (!s) return { color: 'grey', text: 'unknown' }
  if (s.runtime === 'ready' && s.relay_connected) return { color: 'green', text: 'operational' }
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

// -- active-gateway relay panel ---------------------------------------------

function ActiveRelayPanel(props) {
  // All panel state and caches are scoped to one gateway connection: the
  // page remounts this component (React key) when the active connection
  // changes, and the query keys carry the connection id so gateway A's
  // status/devices can never render while gateway B is active (BR-06).
  const [offer, setOffer] = useState(null)
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

  const refresh = useCallback(() => {
    status.refetch()
    devicesQ.refetch()
  }, [status, devicesQ])

  const createOffer = useCallback(() => {
    setBusy(true)
    setErr(null)
    props
      .rest('/pairing-offers', { method: 'POST', body: {} })
      .then((o) => setOffer(o))
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
    return h(
      'div',
      { className: 'mr-card' },
      h('h2', null, 'Relay not available on this gateway'),
      h('div', { className: 'mr-muted' },
        'The active connection has no Mercury Relay backend. Switch to a gateway ' +
          'where the relay plugin is installed and enabled, or install it there.'),
    )
  }

  return h(
    'div',
    null,
    err ? h('div', { className: 'mr-banner mr-error' }, 'Error: ' + err) : null,
    s && s.relay_origin_configured === false
      ? h('div', { className: 'mr-banner' },
          'No relay origin configured on this gateway — pairing works, but the phone ' +
            'cannot connect until the hosted relay origin is set.')
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
            h(QrSvg, { svg: offer.qr_svg }),
            h('div', { style: { flex: '1', minWidth: '200px' } },
              h('div', { className: 'mr-muted' }, 'Offer'),
              h('div', { className: 'mr-fingerprint' }, offer.offer_id),
              h('div', { className: 'mr-muted', style: { marginTop: '10px' } },
                'This QR contains the one-time pairing secret. It is shown once and ' +
                  'never stored or displayed as text.')))
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
  )
}

function QrSvg(props) {
  // The SVG is generated server-side and contains no script; render inline.
  return h('div', {
    className: 'mr-qr',
    dangerouslySetInnerHTML: { __html: props.svg || '' },
  })
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
