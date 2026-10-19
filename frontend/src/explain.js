// Plain-language explanations for each request shown in the security trace.
// Matched on method + path; the status code adds a line about the outcome.

const E = [
  {
    m: 'POST', p: /^\/auth\/login/, title: 'Sign in with a password',
    what: 'The browser sends the username and password. The server checks rate limits and lockout, verifies the password against its argon2id hash, then issues a signed 15-minute access token and a refresh cookie.',
    controls: ['W2 argon2id password hashing', 'W3 IP rate limit + account lockout', 'W4 ES256-signed access token', 'W10 audit log entry'],
    say: 'The password is never stored. The server re-derives the hash from the salt and compares. Five wrong guesses lock the account.',
  },
  {
    m: 'POST', p: /^\/auth\/register/, title: 'Create an account',
    what: 'The password is checked against the policy, hashed with argon2id, and a wallet with Rs 0 is opened. The database only lets a user open a wallet for themselves with a zero balance (RLS insert policy).',
    controls: ['W2 argon2id hashing', 'W1 RLS insert policy', 'W5 strict input schema', 'W10 audit'],
    say: 'Even the wallet creation goes through a row-level security policy, so a client can\'t open a wallet for someone else or with money in it.',
  },
  {
    m: 'POST', p: /^\/auth\/refresh/, title: 'Restore the session',
    what: 'The HttpOnly refresh cookie is exchanged for a new access token. The old refresh token is revoked (rotation). If a revoked one ever comes back, every session in that family is killed because it was stolen.',
    controls: ['W4 refresh-token rotation + reuse detection'],
    say: 'The access token lives only in memory, never in localStorage, so a page reload uses this cookie to get a fresh one.',
  },
  {
    m: 'POST', p: /^\/auth\/logout/, title: 'Sign out',
    what: 'The access token\'s id (jti) goes on a revocation list and the refresh token is revoked, so a copied token stops working immediately instead of at expiry.',
    controls: ['W4 token revocation', 'W10 audit'],
    say: 'After logout, replaying the old token gives 401.',
  },
  {
    m: 'GET', p: /^\/me$/, title: 'Load my profile and balance',
    what: 'Every authenticated request first verifies the token signature and claims, then binds the user id to the database transaction so row-level security only returns this user\'s wallet.',
    controls: ['W4 token verification', 'W1 row-level security'],
    say: 'Look at the ES256 verification math: if one byte of the token changed, x mod n would not equal r.',
  },
  {
    m: 'GET', p: /^\/wallets\//, title: 'Read a wallet by id',
    what: 'Two independent checks stop one customer reading another\'s wallet: the API query filters by the caller\'s id, and Postgres row-level security filters again. A foreign id returns 404, the same as a missing one, so ids can\'t be enumerated.',
    controls: ['W1 ownership filter (API)', 'W1 row-level security (DB)'],
    say: 'This is BOLA, number one on the OWASP API Top 10. Logged in is not the same as allowed.',
  },
  {
    m: 'GET', p: /^\/transactions\/[^?]+/, title: 'Read one transaction',
    what: 'Only returned if you are the sender or receiver: filtered in the API query and again by the RLS policy on the transactions table.',
    controls: ['W1 ownership filter', 'W1 row-level security'],
    say: 'Same two layers as wallets.',
  },
  {
    m: 'GET', p: /^\/transactions/, title: 'Load transaction history',
    what: 'Lists transactions where you are sender or receiver. The RLS step shows how many rows the database policy allowed through.',
    controls: ['W1 ownership filter', 'W1 row-level security'],
    say: 'With both W1 switches off in the lab, other people\'s transfers appear here highlighted in red.',
  },
  {
    m: 'GET', p: /^\/users\/lookup/, title: 'Find a recipient',
    what: 'Checks the username exists and whether you have paid them before (used by the risk engine). Returns only name and username: no ids, no balance. Lookups are rate limited to stop scraping.',
    controls: ['Data minimisation', 'Rate limit'],
    say: 'The response deliberately leaks nothing an attacker could use.',
  },
  {
    m: 'GET', p: /^\/contacts/, title: 'Load recent contacts',
    what: 'People you have sent to or received from, taken from your own transactions only.',
    controls: ['W1 row-level security'],
    say: 'Background request for the home screen.',
  },
  {
    m: 'POST', p: /^\/transfers\/[^/]+\/confirm/, title: 'Approve a transfer with the passkey',
    what: 'The server recomputes the challenge from its own stored copy of the transfer, then checks the device\'s signed response: clientDataJSON (type, challenge, origin), authenticatorData (rpId hash, user-verified flag, counter) and the ECDSA P-256 signature against the stored public key. Only then does the money move, atomically.',
    controls: ['W8 FIDO2 step-up bound to the transfer', 'W7 atomic transfer with row locks', 'W10 audit'],
    say: 'The signature covers this exact amount and payee, once. A phishing site produces a different origin and rpId hash, so it fails.',
  },
  {
    m: 'POST', p: /^\/transfers\/[^/]+\/cancel/, title: 'Cancel a pending transfer',
    what: 'Marks the transfer awaiting passkey approval as cancelled. No money had moved.',
    controls: ['W10 audit'],
    say: 'Nothing leaves the wallet until the passkey approves it.',
  },
  {
    m: 'POST', p: /^\/transfers$/, title: 'Send money',
    what: 'The full Lecture 2 pipeline: verify the token, check the transfer:write scope, look up the Idempotency-Key, validate the amount and recipient on the server, score the risk, then either ask for a passkey (202) or run transfer_funds(), which locks both wallets, debits and credits in one database transaction.',
    controls: ['W4 token', 'W6 idempotency key', 'W5 server-side validation', 'W8 risk engine / step-up', 'W7 atomic transfer', 'W10 audit'],
    say: 'Receiver\'s balance shows as hidden: even inside the trace, RLS stops the sender seeing it.',
  },
  {
    m: 'POST', p: /^\/passkeys\/register\/options/, title: 'Start passkey registration',
    what: 'The server creates a random single-use 32-byte challenge, stores it for 5 minutes, and sends the options (rpId, user verification required, allowed algorithms) to the browser.',
    controls: ['W8 FIDO2 registration'],
    say: 'The challenge makes every registration fresh, so an old response can\'t be replayed.',
  },
  {
    m: 'POST', p: /^\/passkeys\/register\/verify/, title: 'Save the new passkey',
    what: 'The device created a P-256 key pair and returned only the public key. The server checks the challenge, origin, rpId hash and user-verified flag, then stores the public key. The private key never leaves the device.',
    controls: ['W8 FIDO2 registration', 'W1 RLS on passkeys', 'W10 audit'],
    say: 'This is the key sharing: only the public half is shared, so a stolen database is useless for signing in.',
  },
  {
    m: 'GET', p: /^\/passkeys/, title: 'List passkeys',
    what: 'Your registered passkeys (names and dates only), limited to yours by RLS.',
    controls: ['W1 row-level security'], say: 'Background request.',
  },
  {
    m: 'DELETE', p: /^\/passkeys\//, title: 'Remove a passkey',
    what: 'Deletes the public key. RLS makes sure you can only delete your own.',
    controls: ['W1 row-level security', 'W10 audit'], say: '',
  },
  {
    m: 'GET', p: /^\/audit\/reconcile/, title: 'Reconcile the ledger',
    what: 'For every wallet, balance must equal received minus sent, and all balances must add up to the total supply. Runs in a database function that also refuses anyone who is not an auditor.',
    controls: ['W9 role check (API + database)', 'W7 detects lost updates'],
    say: 'After the race-condition attack with locking off, this shows the mismatch: evidence the control matters.',
  },
  {
    m: 'GET', p: /^\/audit/, title: 'Read the audit log',
    what: 'Auditor-only. The log is append-only (a trigger rejects UPDATE/DELETE) and secrets are redacted before writing.',
    controls: ['W9 role-based access', 'W10 audit trail'],
    say: 'Every rejected request is in here too, not just the successful ones.',
  },
  {
    m: 'PUT', p: /^\/lab\/flags\//, title: 'Security lab: switch a control',
    what: 'Turns one control on or off for the before/after demo. RLS and the amount constraint are switched with real SQL (ALTER TABLE). The switch itself is audited.',
    controls: ['Demo only (DEMO_MODE)'], say: 'Outside demo mode this endpoint does not exist.',
  },
  { m: 'POST', p: /^\/lab\/reset/, title: 'Security lab: reset', what: 'Restores every control and the original seed data.', controls: ['Demo only'], say: '' },
  { m: 'GET', p: /^\/lab\/users-table/, title: 'Dump the users table (attacker view)', what: 'Shows what someone with database access would see in the password column.', controls: ['W2 demo'], say: 'With argon2 on you see a salted hash; with it off, the password itself.' },
  { m: 'GET', p: /^\/lab\//, title: 'Security lab data', what: 'Lab state or target ids for the attack buttons.', controls: ['Demo only'], say: '' },
  {
    m: 'BROWSER', p: /registration/, title: 'Browser: create a passkey',
    what: 'navigator.credentials.create() asks the device (Windows Hello, Touch ID, security key) to make a new key pair for this site. You verify with fingerprint, face or PIN locally.',
    controls: ['W8 FIDO2'], say: 'The biometric never leaves the device.',
  },
  {
    m: 'BROWSER', p: /assertion/, title: 'Browser: sign with the passkey',
    what: 'navigator.credentials.get() asks the device to sign the server\'s challenge with its private key after you verify locally. The browser writes the real page origin into clientDataJSON, which is what defeats phishing.',
    controls: ['W8 FIDO2'], say: 'The signed response goes to /confirm, where the server verifies it.',
  },
]

const STATUS = {
  200: 'OK: the request was allowed and completed.',
  201: 'Created: the action succeeded (e.g. money moved).',
  202: 'Accepted but on hold: nothing has happened yet, a passkey approval is needed.',
  400: 'Bad request: the server rejected malformed or failed verification data.',
  401: 'Unauthenticated: the server could not verify who you are (bad password, forged or revoked token).',
  403: 'Forbidden: you are signed in, but not allowed to do this.',
  404: 'Not found: either it doesn\'t exist or it isn\'t yours. The server answers the same way on purpose.',
  409: 'Conflict: a duplicate or already-handled request.',
  410: 'Expired: the approval window closed.',
  422: 'Rejected by validation or business rules. No money moved.',
  429: 'Too many attempts: rate limit or account lockout.',
  500: 'Server error, returned without internal details.',
}

export function explain(entry) {
  const hit = E.find(e => e.m === entry.method && e.p.test(entry.path))
  return {
    title: hit?.title || `${entry.method} ${entry.path}`,
    what: hit?.what || 'A request to the SecureWallet API. The steps below show each security check it passed through.',
    controls: hit?.controls || [],
    say: hit?.say || '',
    outcome: entry.status ? STATUS[entry.status] || `HTTP ${entry.status}` : 'Runs in the browser and on the authenticator: the server never sees these steps.',
  }
}
