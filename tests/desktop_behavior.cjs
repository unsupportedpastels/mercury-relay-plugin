// Execute the shipped plugin with only its host/React boundaries shimmed.
const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const { join } = require('node:path')
const vm = require('node:vm')
const { test } = require('node:test')

function load(query = () => ({})) {
  const element = (type, props) => ({ type, props })
  const ctx = vm.createContext({
    jsx: element, jsxs: element, Button: 'button', Codicon: 'i',
    host: { state: { connectionId: 'local' } },
    useValue: value => value, useQuery: query,
    useState: value => [value, () => {}], useCallback: fn => fn,
  })
  const source = readFileSync(join(__dirname, '../desktop/plugin.js'), 'utf8')
    .replace(/^import[\s\S]*?from ['"][^'"]+['"]\s*$/gm, '')
    .replace('export default', 'const plugin =')
  vm.runInContext(source, ctx, { filename: 'desktop/plugin.js' })
  return ctx
}

function text(node) {
  if (node == null || typeof node === 'boolean') return ''
  if (Array.isArray(node)) return node.map(text).join(' ')
  if (typeof node !== 'object') return String(node)
  if (typeof node.type === 'function') return text(node.type(node.props))
  return text(node.props.children)
}

for (const message of ['404', '404: Not Found', '404: {"error":"unknown"}', 'No such API endpoint']) {
  test(`generic missing API is unknown, not a claim of absent installation: ${message}`, async () => {
    const ctx = load()
    ctx.window = { hermesDesktop: { api: async () => { throw new Error(message) } } }
    const result = await ctx.probeGatewayStatus('remote')
    assert.equal(result.notFoundKind, 'api-unavailable')
    assert.equal(ctx.statusOf(result).text, 'relay API unavailable')
    const body = text(ctx.MissingBackendCard({ error: new Error(message) }))
    assert.match(body, /installation state is unknown/i)
    assert.doesNotMatch(body, /not installed|has no Mercury Relay backend/)
  })
}

test('known disabled/restart and non-404 failures stay distinct', () => {
  const ctx = load()
  assert.equal(ctx.classify404('404: {"detail":"Plugin not found"}'), 'not-enabled')
  assert.equal(ctx.classify404('404: {"detail":"Not Found"}'), 'restart-needed')
  for (const message of ['401: Unauthorized', '403: Forbidden', '500: failed', 'network timeout', 'Headless backend (hermes serve): web UI disabled']) {
    assert.equal(ctx.classify404(message), null)
  }
  assert.equal(ctx.statusOf({ error: 'network timeout' }).color, 'red')
  assert.equal(ctx.statusOf({ notFound: true }).text, 'relay API unavailable')
  assert.equal(ctx.statusOf({ status: { runtime: 'ready', relay_connected: true } }).color, 'green')
})

for (const state of ['loading', 'healthy', 'update-available', '404', 'headless', 'disabled', 'network']) {
  test(`postinstall guidance is visible once on the actual page: ${state}`, () => {
    const errors = {
      '404': '404', headless,
      disabled: '404: {"detail":"Plugin not found"}', network: 'network timeout',
    }
    const ctx = load(options => {
      const key = options.queryKey.at(-1)
      if (key === 'roster') return { data: { rows: [] } }
      if (key === 'update' && state === 'update-available') return { data: {
        installed: '0.2.13', latest: '0.2.14', available: true, install: { kind: 'git' },
      } }
      if (key !== 'status') return {}
      return errors[state] ? { isError: true, error: new Error(errors[state]) }
        : state === 'loading' ? { isLoading: true }
        : { data: { runtime: 'ready', relay_connected: true } }
    })
    const body = text(ctx.MercuryRelayPage({ rest: () => { throw Error('render must not need API') } }))
    assert.equal(body.split('After installing or updating').length - 1, 1)
    for (const pattern of [/finish.*tasks/i, /fully quit.*Hermes Desktop/i, /Cmd\+Q/, /Quit\/Exit/, /reopen/i,
      /closing.*window/i, /reloading.*desktop plugin/i, /hermes gateway restart/, /separate.*hermes serve/, /startup/]) {
      assert.match(body, pattern)
    }
    if (errors[state]) assert.doesNotMatch(body, /Generate QR/)
    if (state === 'healthy') assert.match(body, /Generate QR/)
    if (state === 'update-available') assert.match(body, /Update gateway plugin/)
  })
}

const headless = '404: {"error":"Headless backend (hermes serve): web UI disabled — use `hermes dashboard` for the browser UI."}'

test('headless fallback requests restart in classifier, roster and missing card', async () => {
  const ctx = load()
  ctx.window = { hermesDesktop: { api: async () => { throw new Error(headless) } } }
  const result = await ctx.probeGatewayStatus('local')
  assert.equal(result.notFoundKind, 'restart-needed')
  assert.match(ctx.statusOf(result).text, /restart needed/)
  assert.match(text(ctx.MissingBackendCard({ error: new Error(headless) })), /restart needed/i)
})
