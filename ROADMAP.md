# Roadmap

The plan, broken into shippable phases. **No phase is started until
the previous one is in feedback for at least a week** — this avoids
building features on top of unvalidated decisions.

This roadmap is editable. Open an issue if you'd reorder, drop, or
add a phase.

---

## Phase 0 — Design + vision  ✓ done

**Goal:** know exactly what we're building before we write code.

| Deliverable | Status |
|---|---|
| Repo + vision README | ✅ |
| ASCII wireframes for the 6 core screens | ✅ |
| Stack decision (Tauri 2 + React + Vite + Rust crypto) | ✅ |
| Brand + design tokens (Sigillum palette, Cinzel/Fraunces/JetBrains Mono) | ✅ |
| Interactive HTML preview of variable viewer | ✅ |

---

## Phase 1 — Read-only viewer  ← in progress

**Goal:** open a `.env.sealed` file, see the variables. Nothing else.

| Deliverable | Status | Notes |
|---|---|---|
| React + Vite + TypeScript scaffold | ✅ | strict + exactOptionalPropertyTypes |
| Variable Viewer component | ✅ | filter, mask/reveal, mode badge, health sidebar |
| Tauri project scaffold | 🟡 | src-tauri structure initialized |
| Rust crypto backend (SEALED-ENV-V1) | ⬜ | must pass test vectors at sealed-env/test-vectors/v1/ |
| File picker for `.env.sealed` | ⬜ | Native Tauri dialog |
| Master key input | ⬜ | Never persisted |
| Wire Rust → TS via Tauri IPC | ⬜ | snake_case → camelCase in lib/*.ts |
| Welcome screen + unlock dialog | ⬜ | Phase-2 prep |

**Out of scope for phase 1:** editing, diff, TOTP, anything destructive.

**Exit criteria:**
- Open Studio, point it at the example `.env.sealed` from the main
  repo, paste the demo master key, see all variables. Done.

---

## Phase 2 — Editor + re-seal  (~2 weeks)

**Goal:** edit values and re-seal in place, with proper
confirmations.

| Deliverable | Notes |
|---|---|
| Inline edit per variable | Click → text field → save |
| Add new variable | Form with KEY + value |
| Remove variable | With confirmation |
| Re-seal on save | Calls into `sealed-env` Rust port or subprocess |
| Backup before write | `.env.sealed.bak` like the CLI does |
| Undo last change | Memory-only, lost on close |

**Exit criteria:**
- Edit a value, save, close Studio, re-open. New value persists,
  old `.env.sealed.bak` is on disk.

---

## Phase 3 — Visual diff  (~1 week)

**Goal:** compare two sealed files side-by-side. Useful for prod vs
staging audits.

| Deliverable | Notes |
|---|---|
| Two-pane file picker | "Old" vs "New" |
| Coloured diff: added / removed / changed | Green / red / yellow |
| Mask values by default, "Show" per row | Same masking discipline as viewer |
| Export diff to text | For PR comments / audit reports |

**Exit criteria:**
- Take a recent `.env.sealed` and `.env.sealed.bak`, open both,
  see exactly what changed.

---

## Phase 4 — TOTP enrollment  (~2 weeks)

**Goal:** make enterprise mode enrollment painless. The terminal QR
on Windows often misrenders; Studio renders a perfect QR every
time.

| Deliverable | Notes |
|---|---|
| Run `sealed-env init --mode enterprise` from UI | Capture output, parse keys |
| Display the QR in a window | High-contrast, scannable on first try |
| Verify TOTP flow before commit | "Enter the code your app shows" |
| Save secrets to OS keychain (opt-in) | Reuses CLI's keychain backend |

**Exit criteria:**
- Onboard a new dev to enterprise mode in under 90 seconds, with
  no copy-pasting from terminal logs.

---

## Phase 5 — Doctor integration  (~1 week)

**Goal:** surface `sealed-env doctor` checks (shipping in CLI 0.1.x)
as visual indicators in the app.

| Deliverable | Notes |
|---|---|
| Live status panel | "✓ .env.sealed valid · ⚠ .env.local mode 0644 · …" |
| Click a warning → fix suggestion | "Open chmod dialog?" |
| Background re-check on file change | Watcher on `.env.sealed` and `.env.local` |
| Pre-deploy checklist | "Working tree clean? Token fresh? Health URL set?" |

**Exit criteria:**
- Common misconfigurations are caught visually before the CLI
  would catch them on next invocation.

---

## Phase 6 — Polish + distribution  (~2-3 weeks)

**Goal:** production-grade release.

| Deliverable | Notes |
|---|---|
| App icons (sigillum branding) | Windows .ico, macOS .icns, Linux .png |
| Code signing | Windows Authenticode, macOS Developer ID |
| Notarization (macOS) | Required for Gatekeeper-friendly install |
| Auto-update channel | Tauri's built-in updater |
| GitHub Release with artifacts | `.dmg`, `.msi`, `.AppImage`, `.deb`, `.rpm` |
| Linux package repos (later) | Flathub, AUR |
| App Store / Microsoft Store (much later) | After 1.0 |

**Exit criteria:**
- Anyone on Windows / macOS / Linux can download an installer,
  double-click, and have a signed, notarized app running.
- Updates ship without user intervention.

---

## Beyond v1.0

These are sketches, not commitments:

- **Workspace-style multi-env**: pin prod, staging, dev as tabs.
- **Audit log per-secret**: who edited STRIPE_KEY, when, from what host.
- **Plugin system**: integrate with 1Password, Bitwarden, AWS Secrets
  Manager, HashiCorp Vault as alternative master-key sources.
- **Mobile companion**: just a TOTP code generator that knows about
  your `sealed-env` deployments — never holds keys.
- **Team collaboration**: Studio talking to a self-hosted server for
  signing keys, audit logs, multi-operator workflows. (Possibly a
  separate product entirely.)

---

## Versioning

Studio versions independently of the main `sealed-env` library. The
CLI is on **0.1.0** today; Studio may release its own **0.1.0** when
phase 1 lands.

The wire format (`SEALED-ENV-V1`) is **frozen** in the main project,
so Studio writes files that any version of the CLI can read.

---

## Why this pace

This is a solo open-source project run alongside other work. The
phase estimates assume ~10 hours per week of effort — they could
easily double on a bad month. **Don't take dates seriously; take
the order seriously.**

If you'd like to accelerate any phase, the fastest path is to
contribute. Even a small PR that handles one screen well saves the
maintainer 4+ hours.
