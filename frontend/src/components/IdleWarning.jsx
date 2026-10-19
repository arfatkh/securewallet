// Shown during the last minute before an inactivity sign-out (W13).
// The server enforces the limit; this only gives the user a fair warning.
export default function IdleWarning({ secondsLeft, onStay, onSignOut }) {
  const m = Math.floor(secondsLeft / 60)
  const s = String(secondsLeft % 60).padStart(2, '0')
  return (
    <div className="modal-scrim" role="presentation">
      <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="idle-title" aria-describedby="idle-text">
        <h2 id="idle-title">Are you still there?</h2>
        <p id="idle-text" className="muted">
          For your security you'll be signed out in <b className="num" style={{ color: 'var(--ink)' }}>{m}:{s}</b> because
          there has been no activity.
        </p>
        <button className="btn primary block" onClick={onStay} autoFocus>Stay signed in</button>
        <button className="btn quiet block" onClick={onSignOut}>Sign out now</button>
      </div>
    </div>
  )
}
