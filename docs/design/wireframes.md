# Wireframes

ASCII mockups of the six core screens. Updated as design feedback
accumulates. **Open an issue if you'd change any of these.**

For consistency, the brand language is:

- **Cream** background (`#F1EBE0`)
- **Ink** primary text (`#1A1612`)
- **Wax** accent (`#A8201A`)
- Header serif: Cinzel · Body: Fraunces · Mono: JetBrains Mono

---

## Screen 1 — Welcome / file picker

First-run state. No file open.

```
┌──────────────────────────────────────────────────────────┐
│  ●●●                  sealed-env Studio              □ ✕ │
├──────────────────────────────────────────────────────────┤
│                                                          │
│                       SE                                 │
│                  ◉ sigillum ◉                            │
│                                                          │
│           Welcome to sealed-env Studio                   │
│                                                          │
│        Open or create a sealed .env vault.               │
│                                                          │
│           ┌──────────────────────┐                       │
│           │  📂 Open .env.sealed  │                      │
│           └──────────────────────┘                       │
│                                                          │
│           ┌──────────────────────┐                       │
│           │  ✨ Init new project  │                      │
│           └──────────────────────┘                       │
│                                                          │
│  Recent:                                                 │
│   • ~/work/my-app/.env.sealed         · 2h ago           │
│   • ~/work/staging-deploy/.env.sealed · yesterday        │
│   • ~/personal/blog/.env.sealed       · 3 days ago       │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Screen 2 — Variable list (the "viewer")

The core day-to-day screen. After unlocking a file.

```
┌──────────────────────────────────────────────────────────┐
│  ●●●  ~/work/my-app/.env.sealed              [ team ✓ ] │
├──────────────────────────────────────────────────────────┤
│  🔍 [filter variables...]              [+ Add]  [⋯]      │
├──────────────────────────────────────────────────────────┤
│                                                          │
│   KEY                       VALUE                        │
│   ─────────────────────     ───────────────────────────  │
│   DATABASE_URL              ●●●●●●●●●●●●  [Reveal] [✏]   │
│   STRIPE_KEY                ●●●●●●●●●●●●  [Reveal] [✏]   │
│   STRIPE_WEBHOOK_SECRET     ●●●●●●●●●●●●  [Reveal] [✏]   │
│   JWT_SECRET                ●●●●●●●●●●●●  [Reveal] [✏]   │
│   OPENAI_API_KEY            ●●●●●●●●●●●●  [Reveal] [✏]   │
│   SENDGRID_API_KEY          ●●●●●●●●●●●●  [Reveal] [✏]   │
│   REDIS_URL                 redis://...    [Reveal] [✏]  │
│                                                          │
├──────────────────────────────────────────────────────────┤
│ 7 variables · last sealed 2h ago · KDF: argon2id · v1   │
└──────────────────────────────────────────────────────────┘
```

Notes:
- Values masked with `●` by default. "Reveal" toggles per-row.
- Mode badge top-right (`team ✓` here). Colour-coded: ink for
  basic, wax for team, cream-on-wax for enterprise.
- "Add" creates a new variable. "✏" opens inline editor.

---

## Screen 3 — Inline editor

Triggered by clicking ✏ on a row. Replaces that row.

```
┌──────────────────────────────────────────────────────────┐
│  ●●●  ~/work/my-app/.env.sealed              [ team ✓ ] │
├──────────────────────────────────────────────────────────┤
│   KEY                       VALUE                        │
│   ─────────────────────     ───────────────────────────  │
│   DATABASE_URL              ●●●●●●●●●●●●  [Reveal] [✏]   │
│                                                          │
│   ▼ STRIPE_KEY                                           │
│   ┌────────────────────────────────────────────────────┐ │
│   │ sk_live_51HxqFDD9xXyzAbcDef2Gh...                  │ │
│   └────────────────────────────────────────────────────┘ │
│   ⚠ Note: this changes the sealed file. Backup will be  │
│   written to .env.sealed.bak.                           │
│   [Cancel]                              [Save & Re-seal] │
│                                                          │
│   STRIPE_WEBHOOK_SECRET     ●●●●●●●●●●●●  [Reveal] [✏]   │
└──────────────────────────────────────────────────────────┘
```

---

## Screen 4 — Diff view

Compare two `.env.sealed` files. Useful for prod-vs-staging audits.

```
┌──────────────────────────────────────────────────────────┐
│  ●●●  Compare envs                                       │
├──────────────────────────────────────────────────────────┤
│  LEFT:  staging/.env.sealed       [Change file...]       │
│  RIGHT: prod/.env.sealed          [Change file...]       │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  KEY                  STAGING            PROD            │
│  ──────────────────   ─────────────      ─────────────   │
│  DATABASE_URL         postgres://stg...  postgres://...  │ ✗ different
│  STRIPE_KEY           sk_test_...        sk_live_...     │ ✗ different
│  JWT_SECRET           ●●●●●●●●●          ●●●●●●●●●       │ ✓ same
│  REDIS_URL            redis://localhost  redis://...     │ ✗ different
│  ANALYTICS_KEY        ●●●●●●●●●          (missing)       │ ⊖ removed
│  CDN_TOKEN            (missing)          ●●●●●●●●●       │ ⊕ added
│                                                          │
├──────────────────────────────────────────────────────────┤
│  4 different · 1 same · 1 removed · 1 added              │
│  [Show values] [Export to text] [Open as PR comment]    │
└──────────────────────────────────────────────────────────┘
```

Status icons: `✗` different (wax), `✓` same (ink), `⊖` removed
(faded), `⊕` added (wax).

---

## Screen 5 — TOTP enrollment

Triggered when initialising or upgrading to enterprise mode.

```
┌──────────────────────────────────────────────────────────┐
│  ●●●  Enable enterprise mode (TOTP)                      │
├──────────────────────────────────────────────────────────┤
│                                                          │
│   Step 2 of 3 — Scan with your authenticator             │
│                                                          │
│           ┌────────────────────────────┐                 │
│           │ ███▀▀▀█▀▀█▀█▀█▀▀▀█████     │                 │
│           │ ███   █  ▄▀▄ █   █████     │                 │
│           │ ███▄▄▄█▄▄█▄█▄█▄▄▄█████     │                 │
│           │ ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀     │                 │
│           │  (large, crisp QR code)    │                 │
│           └────────────────────────────┘                 │
│                                                          │
│   Or enter manually:                                     │
│   sealed-env (my-app)                                    │
│   Secret: J B S W   Y 3 D P   E H P K   3 P X P          │
│                                                          │
│   [Copy]                              [Skip — paste URI] │
│                                                          │
│   ─────────────────────────────────────────              │
│   Enter the 6-digit code your app shows now:             │
│   ┌──────────────────┐                                   │
│   │  4 7 9   3 0 2   │                                   │
│   └──────────────────┘                                   │
│                                                          │
│   [← Back]                                  [Verify →]   │
└──────────────────────────────────────────────────────────┘
```

---

## Screen 6 — Health (doctor) panel

Sidebar / always-visible panel. Reflects `sealed-env doctor` state.

```
┌─────────────────────────┐
│  Health                 │
├─────────────────────────┤
│  ✓ .env.sealed valid    │
│  ✓ master key reachable │
│  ⚠ .env.local mode 0644 │
│    (should be 0600)     │
│    [Fix]                │
│  ✓ git ignores .env     │
│  ✓ wire format up to date│
│  ⚠ alpha.6 in deps      │
│    Newer 0.1.0 available│
│    [Upgrade]            │
│                         │
│  Last check: 2s ago     │
│  [Re-run]               │
└─────────────────────────┘
```

Probably docked to the right side of the main viewer, collapsible.

---

## Open design questions

These deserve input:

1. **Master key entry.** First-run: paste? environment variable?
   Drop a key file? OS keychain unlock?
2. **Multi-file workspace.** Should Studio remember "this project
   has dev + staging + prod" so you can switch without re-picking?
3. **Diff for non-text values.** What if someone has a 50KB
   base64-encoded blob in their env? Mask differently?
4. **Audit log.** Phase 6+? Or a separate companion?
5. **Mobile counterpart.** Does Studio have a phone app for TOTP
   review only? Or stay desktop?
6. **Theme.** Hard commit to the cream/ink/wax sigillum brand or
   support light/dark/auto?

Open issues with the `[design]` prefix to weigh in.

---

## What this isn't

These wireframes deliberately omit:

- Login / signup / account
- Cloud sync
- "Suggest a stronger value" AI
- Public sharing of secrets
- Anything that implies a backend

Studio is a **local desktop app for your own files**. Adding any of
the above would be a different product.
