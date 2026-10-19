# SecureWallet redesign — "Ledger" design spec (shared contract for all agents)

Concept: an editorial, private-banking ledger. Warm paper background, deep ink text,
a single strong cobalt accent, serif display headings, generous whitespace, ruled
lines like an account book. Must feel nothing like the old jade/sidebar look.
Priority #1 is readability: 16px base text, high contrast, clear hierarchy.

## Fonts (already installed via npm; foundation agent imports them in main.jsx)
- Display/headings & big money figures: `"Fraunces Variable", Georgia, serif`  → `var(--display)`
- Body/UI: `"IBM Plex Sans", system-ui, sans-serif` (weights 400/500/600/700) → `var(--font)`
- Code / hashes / IDs: `"IBM Plex Mono", ui-monospace, monospace` (400/600) → `var(--mono)`

## Tokens (defined on :root in src/styles.css by the foundation agent — USE THESE, never hardcode colors)
--paper #F6F2EA (page bg) · --surface #FFFDF8 (cards) · --surface-2 #EFE9DD (wells, table heads)
--ink #16181D (text) · --ink-2 #3A3E47 · --muted #6A6E78 · --faint #9A9DA5
--rule #E2DACB (hairlines) · --rule-2 #CFC5B2 (stronger borders)
--accent #2747D6 (cobalt: primary actions, links, focus) · --accent-ink #1A2F94 · --accent-soft #E4E9FD
--night #12152B (dark hero blocks, e.g. balance card / auth panel) · --night-2 #1E2245 · --brass #C9A55A (fine detail on dark only)
--ok #1F7A4D / --ok-soft #DFF1E6 · --warn #A15C00 / --warn-soft #FBEBD0 (= "needs your approval") · --bad #B3261E / --bad-soft #FBE3E0
--r-sm 6px · --r 10px · --r-lg 16px · --shadow (subtle, warm)
Spacing scale: 4/8/12/16/24/32/48/64.

## Shared generic classes (foundation keeps these NAMES so pages keep working; restyles them)
btn (+ primary, quiet, danger, sm, block), field, input, input-wrap, peek, hint, error,
banner (error/warn/ok), card, card-pad, section-title, eyebrow, pill (ok/warn/bad/info/neutral),
avatar (+tint classes), num, mono, muted, sr, switch, menu*, page container `.page`.
New shared helpers foundation adds: `.display` (serif heading style), `.rule` (hairline divider),
`.stack` (vertical gap 16px), `.row` (flex gap 12 center), `.grid-2` (responsive 2-col).

## Layout (foundation)
- No left sidebar. A slim top masthead: wordmark left ("SecureWallet" set in Fraunces with a small
  cobalt seal mark), horizontal nav tabs in the middle (active tab = ink text + 2px cobalt underline),
  user menu right. Below it, the page title rendered large in Fraunces.
- Content max-width 1120px centered, 24px side padding (16px on phone).
- Mobile (<760px): masthead collapses, bottom tab bar stays (class `tabbar`).

## Rules for page agents
- Put page-specific CSS in a NEW file next to the page, e.g. `src/pages/Home.css`, and
  `import './Home.css'` at the top of the page. Prefix classes with the page name (`home-…`, `send-…`).
- Do NOT edit src/styles.css, main.jsx, Shell.jsx, Bits.jsx, Icons.jsx (foundation owns them).
- Do NOT change any logic: API calls, state, handlers, routing, WebAuthn, trace calls, props, text that
  tests/security depend on. Only markup structure, classNames and presentation. Keep accessibility attrs.
- Money amounts: Fraunces, tabular figures. Hashes/IDs: mono.
- Colors only via tokens above. Light theme only.
