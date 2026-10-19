// API client. The access token lives only in this module's memory (never
// localStorage), so an XSS payload can't lift it from storage. The session is
// restored on reload from the HttpOnly refresh cookie.
import { traceStore } from './trace.js'

let accessToken = null
let refreshing = null
let lastLoss = null // why the server ended the session, e.g. {code: 'session_idle', detail}
let onAuthLost = () => {}

export class ApiError extends Error {
  constructor(status, message, data) {
    super(message)
    this.status = status
    this.data = data
  }
}

export function setAccessToken(t) { accessToken = t }
export function getAccessToken() { return accessToken }
export function onSessionLost(fn) { onAuthLost = fn }

async function send(path, { method = 'GET', body, headers = {}, token, label }) {
  const h = { 'X-Requested-With': 'securewallet', ...headers }
  if (body !== undefined) h['Content-Type'] = 'application/json'
  const tk = token === undefined ? accessToken : token
  if (tk) h.Authorization = `Bearer ${tk}`
  const tracing = traceStore.enabled()
  if (tracing) h['X-Security-Trace'] = '1'
  const started = performance.now()
  const sentAt = new Date()
  const flow = traceStore.currentFlow() // captured at send time, not when the response lands
  const res = await fetch('/api' + path, {
    method, headers: h, credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  let data = null
  try { data = await res.json() } catch { /* empty body */ }
  if (data && data._trace) {
    if (tracing) {
      traceStore.push({ at: sentAt, flow, method, path, status: res.status, label, ms: Math.round(performance.now() - started), steps: data._trace })
    }
    delete data._trace
  }
  return { status: res.status, data, headers: res.headers }
}

export async function refreshSession() {
  if (!refreshing) {
    refreshing = send('/auth/refresh', { method: 'POST', token: null, label: 'Restore session' })
      .then(r => {
        if (r.status === 200) { accessToken = r.data.access_token; lastLoss = null; return r.data }
        accessToken = null
        lastLoss = r.data
        return null
      })
      .finally(() => { refreshing = null })
  }
  return refreshing
}

// Throws ApiError on non-2xx. Retries once after a silent refresh on 401.
export async function api(path, opts = {}) {
  let r = await send(path, opts)
  if (r.status === 401 && opts.token === undefined && String(r.data?.code || '').startsWith('session_')) {
    onAuthLost(r.data) // W13: idle or expired on the server; refreshing can't revive it
  } else if (r.status === 401 && opts.token === undefined && !path.startsWith('/auth/')) {
    const s = await refreshSession()
    if (s) r = await send(path, opts)
    else onAuthLost(lastLoss)
  }
  if (r.status >= 400) throw new ApiError(r.status, r.data?.detail || `Request failed (${r.status})`, r.data)
  return r.data
}

// Never throws; used by the security lab where the status code is the point.
export async function apiRaw(path, opts = {}) {
  try { return await send(path, opts) } catch (e) { return { status: 0, data: { detail: String(e) } } }
}

export function newIdempotencyKey() { return crypto.randomUUID() }
