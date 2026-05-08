# Contributing to sealed-env Studio

This repo is in **pre-alpha** and the most valuable thing you can
contribute right now is **opinion**, not code. Read on.

## What we need most (in priority order)

1. **UX critique on the [wireframes](docs/design/wireframes.md).**
   Even one screen reviewed honestly helps. "I don't understand the
   diff view" is a perfectly good comment.
2. **Use cases we missed.** Open an issue with the format:
   *"Scenario: [what you're trying to do]. Today I would: [CLI
   commands]. Studio should help by: [your idea]."*
3. **High-fidelity mockups.** If you're a designer, a Figma file
   for any one screen is enormous value.
4. **Stack experience reports.** Have you shipped a Tauri 2.x app
   on macOS / Windows / Linux? What hurt? Open an issue.
5. **Once Phase 1 starts:** Rust + React PRs.

## How to give feedback

### Issue templates

We don't have templates yet (this repo is days old). For now use
plain text and one of these prefixes in the title:

- **[design]** — feedback on wireframes / UX / mockups
- **[scenario]** — a use case Studio should support
- **[stack]** — opinions on Tauri / React / Rust integration
- **[bug]** — only after Phase 1 ships
- **[idea]** — anything else

### Pull requests

PRs welcome on documentation any time. PRs on code only make sense
after Phase 1 is underway — open an issue first to coordinate.

## Code of Conduct

Same as the main project: be excellent to each other. No politics,
no drive-by negativity, no AI-generated PR spam. Critique work, not
people.

If you want to build collaboratively, default to public discussion.
Issues > DMs > closed-room calls.

## Setting up the dev environment

**Not yet — Phase 1 hasn't started.**

When it does, the setup will look something like this:

```bash
# Prerequisites: Rust toolchain + Node 20+
git clone https://github.com/davidalmeidac/sealed-env-studio
cd sealed-env-studio
npm install
npm run tauri dev
```

We'll write a proper `docs/development.md` once the scaffold lands.

## What kind of feedback we don't need

- "Why not Electron?" — read the README's stack section first. If
  you still disagree, open a `[stack]` issue with concrete reasons.
- "Why not a web app?" — Studio handles a master key. Local
  desktop is a deliberate choice for that key never to touch a
  remote server.
- "Add login / sign up / accounts" — Studio has no backend. There's
  nothing to log into.
- "Use blockchain / AI / [trend]" — please don't.

## Commit conventions

We follow Conventional Commits **loosely**:

```
feat: add diff view skeleton
fix: handle missing master key gracefully
docs: clarify Phase 1 scope in ROADMAP
chore: bump tauri to 2.1
```

Scope is optional. Body is encouraged for non-trivial changes.

## License

By contributing you agree your contributions are MIT-licensed (same
as the project). No CLA.

## Questions

Open an issue. There is no Discord / Slack / Telegram / X / Reddit
thread for this project (yet). Issues are the canonical place.
