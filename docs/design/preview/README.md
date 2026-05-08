# Visual preview

A static, clickable HTML mockup of Studio's main screen — the
**Variable Viewer**.

```
docs/design/preview/
├── index.html       ← open this in any browser
├── screenshot.png   ← rendered preview (1280×900)
└── README.md        ← you are here
```

## How to view

```sh
# Open directly in your browser
open docs/design/preview/index.html        # macOS
xdg-open docs/design/preview/index.html    # Linux
start docs/design/preview/index.html       # Windows
```

Or just double-click `index.html` from your file manager. **No
build step, no install, no server.** It's a single self-contained
HTML file.

## What's interactive

- Click **Reveal** on any masked row → toggles to a fake plaintext
  value (so you can see how the cell wraps and how the action
  buttons feel).
- Click **Hide** → re-masks.
- Hover any row → action buttons fade in.

## What this is, and isn't

**Is:**
- A faithful render of how the brand identity (cream paper, ink
  text, wax accents, sigillum typography) translates to a desktop
  UI.
- A reference for anyone implementing the Tauri app — colours,
  spacing, typography are all in CSS variables.
- A shareable artifact for design feedback and social media.

**Isn't:**
- Real Tauri code. The real app will use React + Tauri 2.x.
- Connected to a real `.env.sealed` file. All values are toy.
- A complete UI — only one screen. The other 5 in
  [wireframes.md](../wireframes.md) are still ASCII.

## Brand tokens used

```css
--cream:    #f1ebe0;   /* primary background */
--cream-2:  #e8e0d2;   /* secondary surfaces */
--ink:      #1a1612;   /* primary text */
--ink-2:    #4a3f38;   /* muted text */
--ink-3:    #7d6f64;   /* faded text / hints */
--wax:      #a8201a;   /* primary accent */
--wax-dark: #7a1411;   /* hover state */
--wax-soft: #c4471f;   /* labels */
```

```css
--font-head: 'Cinzel', 'Trajan Pro', serif;        /* lapidary roman caps */
--font-body: 'Fraunces', 'Cambria', serif;         /* italic-leaning serif */
--font-mono: 'JetBrains Mono', 'Menlo', monospace; /* keys & values */
```

## Feedback wanted

Open an issue with `[design]` in the title if any of these is true:

- The contrast hurts your eyes (especially on light/dark display
  modes — currently we lean light)
- The information density feels wrong (too sparse? too crammed?)
- The colour-coding of mode badges (basic ink, team wax, enterprise
  ink+wax-ring) doesn't read well
- You'd reorder columns (key / value / actions)
- The Health sidebar feels noisy / irrelevant
- The font choice fails on your platform

Any one-paragraph reaction helps.
