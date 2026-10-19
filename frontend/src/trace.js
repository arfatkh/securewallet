// Tiny external store for the Security Trace panel.
// Requests are grouped into "flows": one user action (sign in, a transfer, a
// lab attack) and every request it triggers, so the panel can filter by action.
import { useSyncExternalStore } from 'react'

const KEY = 'sw.presenter'
const read = () => { try { return sessionStorage.getItem(KEY) === '1' } catch { return false } }

let state = { on: read(), available: false, entries: [], flows: [], filter: null, stepMode: false }
let current = null
const subs = new Set()
const emit = () => subs.forEach(fn => fn())
let seq = 0
let flowSeq = 0

export const traceStore = {
  subscribe(fn) { subs.add(fn); return () => subs.delete(fn) },
  get() { return state },
  enabled() { return state.on && state.available },
  setAvailable(v) { state = { ...state, available: v }; emit() },
  setOn(v) {
    try { sessionStorage.setItem(KEY, v ? '1' : '0') } catch { /* private mode */ }
    state = { ...state, on: v }; emit()
  },
  setStepMode(v) { state = { ...state, stepMode: v }; emit() },
  currentFlow() { return current },
  setFilter(id) { state = { ...state, filter: id }; emit() },

  // Start a new flow; every request until the next beginFlow belongs to it.
  beginFlow(label, kind = 'action') {
    const flow = { id: ++flowSeq, label, kind, at: new Date(), ref: null }
    current = flow.id
    state = { ...state, flows: [flow, ...state.flows].slice(0, 60) }
    emit()
    return flow.id
  },
  // Attach details learned later, e.g. the TX reference once a transfer completes.
  tagFlow(patch, id = current) {
    state = { ...state, flows: state.flows.map(f => (f.id === id ? { ...f, ...patch } : f)) }
    emit()
  },
  push(entry) {
    state = { ...state, entries: [{ id: ++seq, at: new Date(), flow: current, ...entry }, ...state.entries].slice(0, 200) }
    emit()
  },
  // Browser-side steps (WebAuthn ceremony) that the server can't see.
  client(label, steps) {
    if (!this.enabled()) return
    this.push({ method: 'BROWSER', path: label, status: 0, label, steps: steps.map((s, i) => ({ seq: i + 1, layer: 'L1', status: 'info', ...s })) })
  },
  clear() { state = { ...state, entries: [], filter: null }; emit() },
}

export function useTrace() {
  return useSyncExternalStore(traceStore.subscribe, traceStore.get)
}
