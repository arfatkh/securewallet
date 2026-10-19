import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { api, onSessionLost, refreshSession, setAccessToken } from './api.js'
import IdleWarning from './components/IdleWarning.jsx'
import { traceStore } from './trace.js'

const Ctx = createContext(null)
const ACTIVITY = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart', 'wheel']
const WARN_SECONDS = 60

export function SessionProvider({ children }) {
  const [status, setStatus] = useState('loading') // loading | anon | ready
  const [me, setMe] = useState(null)
  const [config, setConfig] = useState({ demo_available: false, limits: {} })
  const [signedOutReason, setSignedOutReason] = useState('')
  const [warnLeft, setWarnLeft] = useState(null)
  const lastActivity = useRef(Date.now())
  const lastBeat = useRef(Date.now())
  const paused = useRef(false) // the lab's W13 attack sits idle on purpose

  const loadMe = useCallback(async () => {
    const data = await api('/me')
    setMe(data)
    return data
  }, [])

  const loadConfig = useCallback(async () => {
    const cfg = await api('/config', { token: null })
    setConfig(cfg)
    traceStore.setAvailable(!!cfg.demo_available)
    return cfg
  }, [])

  const endLocally = useCallback(reason => {
    setAccessToken(null)
    setMe(null)
    setWarnLeft(null)
    setSignedOutReason(reason || '')
    setStatus('anon')
  }, [])

  useEffect(() => {
    // The server ended the session (idle, expired, revoked): its message explains why.
    onSessionLost(info => endLocally(info?.code === 'session_idle' ? info.detail : ''))
    ;(async () => {
      try { await loadConfig() } catch { /* API down: the login screen shows the error on submit */ }
      traceStore.beginFlow('Restore session on page load', 'page')
      const s = await refreshSession().catch(() => null)
      if (s) {
        try { await loadMe(); setStatus('ready'); return } catch { /* fall through */ }
      }
      setStatus('anon')
    })()
  }, [loadMe, loadConfig, endLocally])

  // Presenter shortcut works everywhere, including the sign-in screen, so sign-in itself can be traced.
  useEffect(() => {
    if (!config.demo_available) return
    const onKey = e => {
      if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'd') { e.preventDefault(); traceStore.setOn(!traceStore.get().on) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [config.demo_available])

  // W13 inactivity: real user input counts as activity and is reported to the server by a
  // throttled heartbeat; a quiet minute before the limit, the user is warned; at the limit,
  // the app signs out. The server enforces the same limit on its own.
  const idleLimit = config.session?.idle_seconds || 300
  const enforced = config.session?.enforced !== false
  const heartbeat = useCallback(async () => {
    lastBeat.current = Date.now()
    try { await api('/auth/heartbeat', { method: 'POST', label: 'Activity heartbeat' }) } catch { /* handled by onSessionLost */ }
  }, [])

  useEffect(() => {
    if (status !== 'ready') return
    lastActivity.current = Date.now()
    const onActivity = () => { lastActivity.current = Date.now() }
    ACTIVITY.forEach(ev => window.addEventListener(ev, onActivity, { passive: true }))
    const beatEvery = Math.max(5, Math.min(30, idleLimit / 3)) * 1000
    const tick = setInterval(() => {
      if (paused.current || !enforced) { setWarnLeft(null); return }
      const now = Date.now()
      const idleFor = (now - lastActivity.current) / 1000
      if (lastActivity.current > lastBeat.current && now - lastBeat.current >= beatEvery) heartbeat()
      const left = Math.ceil(idleLimit - idleFor)
      if (left <= 0) {
        traceStore.beginFlow('Signed out after inactivity', 'auth')
        api('/auth/logout', { method: 'POST', body: {} }).catch(() => {})
        const minutes = Math.round(idleLimit / 60)
        const span = idleLimit < 60 ? `${idleLimit} seconds` : `${minutes} minute${minutes === 1 ? '' : 's'}`
        endLocally(`You were signed out after ${span} of inactivity.`)
      } else {
        setWarnLeft(left <= Math.min(WARN_SECONDS, idleLimit / 2) ? left : null)
      }
    }, 1000)
    return () => {
      clearInterval(tick)
      ACTIVITY.forEach(ev => window.removeEventListener(ev, onActivity))
    }
  }, [status, idleLimit, enforced, heartbeat, endLocally])

  const stay = useCallback(() => {
    lastActivity.current = Date.now()
    setWarnLeft(null)
    heartbeat()
  }, [heartbeat])

  const signIn = useCallback(async (session) => {
    setAccessToken(session.access_token)
    setSignedOutReason('')
    await loadMe()
    setStatus('ready')
  }, [loadMe])

  const signOut = useCallback(async (everywhere = false) => {
    traceStore.beginFlow(everywhere ? 'Sign out everywhere' : 'Sign out', 'auth')
    try { await api('/auth/logout', { method: 'POST', body: { everywhere } }) } catch { /* already gone */ }
    endLocally('')
  }, [endLocally])

  const pauseIdle = useCallback(v => { paused.current = v; if (!v) lastActivity.current = Date.now() }, [])

  return (
    <Ctx.Provider value={{ status, me, config, reload: loadMe, reloadConfig: loadConfig, signIn, signOut,
                           signedOutReason, pauseIdle }}>
      {children}
      {status === 'ready' && warnLeft != null && (
        <IdleWarning secondsLeft={warnLeft} onStay={stay} onSignOut={() => signOut(false)} />
      )}
    </Ctx.Provider>
  )
}

export const useSession = () => useContext(Ctx)
