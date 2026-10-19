import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useSession } from '../session.jsx'
import { traceStore, useTrace } from '../trace.js'
import { Avatar } from './Bits.jsx'
import * as Icon from './Icons.jsx'
import TraceDrawer from './TraceDrawer.jsx'

const TITLES = { '/': 'Home', '/send': 'Send money', '/activity': 'Activity', '/security': 'Security',
                 '/audit': 'Audit log', '/lab': 'Security lab' }
const titleFor = p => TITLES[p] || (p.startsWith('/wallet/') ? 'Wallet details' : 'SecureWallet')

function UserMenu({ me, onSignOut, presenter, presenterAvailable }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    if (!open) return
    const close = e => { if (!ref.current?.contains(e.target)) setOpen(false) }
    const esc = e => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('mousedown', close); document.removeEventListener('keydown', esc) }
  }, [open])
  return (
    <div className="menu-anchor" ref={ref}>
      <button className="menu-btn" onClick={() => setOpen(o => !o)} aria-expanded={open} aria-haspopup="menu">
        <Avatar name={me.user.full_name} seed={me.user.username} size={32} />
        <span className="who">{me.user.full_name.split(' ')[0]}</span>
      </button>
      {open && (
        <div className="menu" role="menu">
          <div className="head">
            <div style={{ fontWeight: 650 }}>{me.user.full_name}</div>
            <div className="hint">@{me.user.username} · {me.user.role === 'auditor' ? 'Audit team' : 'Personal account'}</div>
          </div>
          {me.user.role === 'customer' && (
            <NavLink className="item" to="/security" onClick={() => setOpen(false)}><Icon.Shield size={18} />Security & passkeys</NavLink>
          )}
          {presenterAvailable && (
            <div className="item" style={{ cursor: 'default' }}>
              <Icon.Trace size={18} />
              <span>Presenter tools<br /><span className="hint">Security trace + lab · Ctrl+Shift+D</span></span>
              <button className="switch" role="switch" aria-checked={presenter} aria-label="Presenter tools"
                      onClick={() => traceStore.setOn(!presenter)} />
            </div>
          )}
          <div className="sep" />
          <button className="item" onClick={() => onSignOut(false)}><Icon.Out size={18} />Sign out</button>
        </div>
      )}
    </div>
  )
}

export default function Shell() {
  const { me, signOut, config } = useSession()
  const { on } = useTrace()
  const presenterAvailable = !!config.demo_available
  const presenter = on && presenterAvailable
  const [drawerOpen, setDrawerOpen] = useState(false)
  const loc = useLocation()
  const isAuditor = me.user.role === 'auditor'

  // Each page visit starts a flow, so background requests are grouped under the page that made them.
  // Layout effect: runs before the page's own data-loading effects, so they land in this flow.
  useLayoutEffect(() => { traceStore.beginFlow(`Open ${titleFor(loc.pathname)}`, 'page') }, [loc.pathname])


  const nav = isAuditor
    ? [['/audit', 'Audit log', Icon.Ledger]]
    : [['/', 'Home', Icon.Home], ['/send', 'Send money', Icon.Send], ['/activity', 'Activity', Icon.Activity], ['/security', 'Security', Icon.Shield]]

  const today = new Date().toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })

  return (
    <div className={`shell ${presenter ? 'with-trace' : ''}`}>
      <div className="main">
        <header className="masthead">
          <div className="masthead-inner">
            <NavLink to={isAuditor ? '/audit' : '/'} className="brand" aria-label="SecureWallet home">
              <Icon.Logo size={30} /><span>SecureWallet</span>
            </NavLink>
            <nav className="topnav" aria-label="Main">
              {nav.map(([to, label]) => (
                <NavLink key={to} to={to} end={to === '/'} title={label}><span>{label}</span></NavLink>
              ))}
              {presenter && (
                <NavLink to="/lab" className="lab" title="Security lab"><Icon.Flask size={16} /><span>Security lab</span></NavLink>
              )}
            </nav>
            <div className="masthead-actions">
              {presenter && <button className="presenter-chip" onClick={() => setDrawerOpen(o => !o)}><Icon.Trace size={15} />Presenter</button>}
              <UserMenu me={me} onSignOut={signOut} presenter={presenter} presenterAvailable={presenterAvailable} />
            </div>
          </div>
        </header>

        <div className="page-head">
          <div className="page-head-inner">
            <div className="eyebrow">{isAuditor ? 'Audit team' : today}</div>
            <h1 className="page-title display">{titleFor(loc.pathname)}</h1>
          </div>
        </div>

        <main className="content">
          <Outlet />
        </main>

        <footer className="shell-foot">
          <div className="shell-foot-inner">
            {!isAuditor && (
              <p className="shell-note">
                <Icon.Lock size={16} />
                <span>Transfers above Rs 50,000, or larger first payments to someone new, need your passkey.</span>
              </p>
            )}
            <p className="shell-mark"><span className="display">SecureWallet</span></p>
          </div>
        </footer>
      </div>

      {presenter && <TraceDrawer open={drawerOpen} />}
      {presenter && (
        <button className="btn primary trace-fab" onClick={() => setDrawerOpen(o => !o)}><Icon.Trace size={18} />Trace</button>
      )}

      <nav className="tabbar" aria-label="Main">
        {nav.map(([to, label, Ico]) => (
          <NavLink key={to} to={to} end={to === '/'}><Ico size={22} />{label.split(' ')[0]}</NavLink>
        ))}
        {presenter && <NavLink to="/lab"><Icon.Flask size={22} />Lab</NavLink>}
      </nav>
    </div>
  )
}
