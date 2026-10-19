import '@fontsource-variable/fraunces/opsz.css'
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource/ibm-plex-sans/600.css'
import '@fontsource/ibm-plex-sans/700.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/600.css'
import './styles.css'
import './passbook.css'

import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import Shell from './components/Shell.jsx'
import Activity from './pages/Activity.jsx'
import Audit from './pages/Audit.jsx'
import { Login, Register } from './pages/Auth.jsx'
import Home from './pages/Home.jsx'
import Lab from './pages/Lab.jsx'
import Security from './pages/Security.jsx'
import Send from './pages/Send.jsx'
import WalletDetails from './pages/WalletDetails.jsx'
import { SessionProvider, useSession } from './session.jsx'
import { useTrace } from './trace.js'
import { Logo } from './components/Icons.jsx'

function Splash() {
  return (
    <div className="splash" role="status" aria-label="Loading SecureWallet">
      <Logo size={52} />
      <div className="splash-word display">SecureWallet</div>
      <div className="splash-rule" aria-hidden="true"><span /></div>
    </div>
  )
}

// Re-mount on every navigation to /send, so the nav link always starts a fresh transfer.
function SendRoute() {
  return <Send key={useLocation().key} />
}

function App() {
  const { status, me } = useSession()
  const { on, available } = useTrace()
  if (status === 'loading') return <Splash />
  if (status === 'anon') {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }
  const auditor = me.user.role === 'auditor'
  return (
    <Routes>
      <Route element={<Shell />}>
        {auditor ? (
          <>
            <Route path="/audit" element={<Audit />} />
            <Route path="*" element={<Navigate to="/audit" replace />} />
          </>
        ) : (
          <>
            <Route path="/" element={<Home />} />
            <Route path="/send" element={<SendRoute />} />
            <Route path="/activity" element={<Activity />} />
            <Route path="/security" element={<Security />} />
            <Route path="/wallet/:id" element={<WalletDetails />} />
            {on && available && <Route path="/lab" element={<Lab />} />}
            <Route path="*" element={<Navigate to="/" replace />} />
          </>
        )}
      </Route>
    </Routes>
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <SessionProvider>
        <App />
      </SessionProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
