# Mobile View Support — Design & Implementation Plan

> Status: **implemented (Phases 1 & 2).** Responsive layer landed as additive `@media` blocks at the
> end of `styles.css` plus a bottom tab bar and process-card `data-label`s. Verified with Playwright at
> 360×780 / 410px and confirmed desktop (>660px) unchanged. Companion to `IMPROVEMENTS.md`.
>
> **Deviation:** Phase 2 stacked-card tables were applied to the **Processes** table only. The
> **Container** table was intentionally kept on Phase-1 horizontal-scroll (its compose nesting,
> colspan sub-process rows, and action/category cells make a card transform fragile on the marquee
> view). The bottom nav uses **4 tabs + Menu** (Docker / Processes / Disk / Network + drawer for the
> rest) rather than a pure drawer replacement, since nested sections don't fit a fixed bar.

## Context

nas-monitor is currently **desktop-only**: `styles.css` has **zero `@media` queries**, and the app is
a fixed-height, non-scrolling shell (`html,body{height:100%;overflow:hidden}`, `styles.css:59`) with a
fixed sidebar rail that pushes `header`/`main` via `margin-left`. On a phone the rail wastes width,
wide data tables overflow, side-by-side flex panels are unusable, and nothing reflows.

**Home Ledger** (`/volume1/system/home-ledger`) — nas-monitor's sibling design system — already solves
this. Its responsive system is documented in `home-ledger/DESIGN.md` §5 and implemented in
`frontend/styles/{app,filters,tables}.css`. It is the reference to mirror.

**Goal:** add a responsive layer so the existing UI is fully usable on phones, in two shippable phases.

**Non-goals:** no new features, no backend/API changes, no redesign of the desktop layout. All mobile
rules are additive (`@media` blocks) and must not change the appearance at desktop widths.

## Decisions

- **Phased rollout** — Phase 1 (usable) then Phase 2 (full Home-Ledger-style polish).
- **Tables → stacked cards** (HL-style) is the eventual target for the wide tables.
- **Breakpoints:** adopt Home Ledger's house standard — **≤660px** (mobile) and **≤410px** (tighten),
  with an optional **≤900px** tablet tweak only if needed. Primary test target **360×780**.

## Current-state map (what each area needs)

| Area | Markup / CSS today | Mobile problem | Treatment |
|---|---|---|---|
| App shell | `html,body{overflow:hidden}` (`styles.css:59`); `main` flex column (`styles.css:549`) | Page can't scroll; fixed regions clip | Allow document scroll on mobile, or keep shell + ensure each `.tab-panel` scrolls internally |
| Sidebar | `.sidebar` fixed 69↔201px; `header`/`main` `margin-left` (`styles.css:183,200,416`) | Rail wastes width; no width trigger | **P1:** off-canvas drawer (slide-in + backdrop). **P2:** bottom tab bar (HL `app.css` mobile rail, `--mnav`) |
| Header metrics | `.metrics-strip` 7 × `.metric-card`, `flex-wrap` (`styles.css:95`, `index.html:373`) | Cramped / over-wraps | 2-col grid or horizontal scroll-snap row; shrink `--fs-metric` |
| Data tables | `.table-wrap{overflow:auto}` + `table` (containers/processes, `index.html:527,587`) | Too wide; columns truncate | **P1:** `overflow-x` scroll + hint. **P2:** `≤660px` rows → stacked cards (thead hidden, key fields stacked) |
| Toolbars | `.toolbar`/`.container-toolbar` flex row (`styles.css:1978`, `index.html:512`) | Buttons overflow | Wrap; **P2:** icon-only (hide `<span>` labels) |
| Disk / Network / Categories | side-by-side flex panels w/ inline `flex:1` (`index.html:643,649,707,728`) | Two columns don't fit | Stack to single column; panels `width:100%`; toggle list/detail |
| Modals | 5 surfaces, fixed width + `max-width:9Xvw` (`styles.css:1217`, `950`, `1174`, `926`, `1233`) | Width OK; 2-col form grids tight | `max-width:96vw; max-height:92vh`; form grids → single column |
| Console / pull terminal | xterm `#console-terminal` fixed (`index.html:265,279`) | Doesn't fit / hard to use | Full-screen sheet on mobile; re-fit `FitAddon` on resize/orientation |
| Tab bar / live badge | `.tab-bar` (`styles.css:131`) | Secondary; minor | Allow wrap / hide non-essential meta |

## Phase 1 — Make it usable (minimal, CSS-mostly)

Append a single `@media (max-width:660px)` section at the **end** of `styles.css` (grouped so desktop
CSS is untouched):

1. **Shell:** relax `overflow` so content scrolls vertically on mobile; collapse the `margin-left`
   offsets on `header`/`main` to `0`.
2. **Navigation:** convert the rail to an **off-canvas drawer** — `.sidebar` slides in over content
   with a tap backdrop; add a hamburger trigger in `header`. Reuse the existing `toggleSidebar()`
   (`ui/menu.js` / `ui/menu-ui.js`) state class; add a `body.sidebar-open` modifier rather than new
   JS logic.
3. **Header metrics:** `.metrics-strip` → 2-col grid (or scroll-snap row); reduce paddings.
4. **Tables:** wrap in `overflow-x:auto` with a subtle scroll affordance — no structural change yet.
5. **Toolbars/filters:** `flex-wrap:wrap`; full-width primary buttons.
6. **Panels:** disk/network/categories flex rows → `flex-direction:column`, panels `width:100%`.
7. **Modals:** `width:auto; max-width:96vw; max-height:92vh`; `.form-grid` / 2-col → single column.

Outcome: every view reachable and operable at 360px; tables scroll sideways. Mostly CSS; the nav
drawer needs only a tiny class toggle (no business logic touched).

## Phase 2 — Full responsive polish (Home-Ledger parity)

1. **Bottom tab bar** for primary sections (replace the drawer with an HL-style fixed bottom nav,
   icon+label; `≤410px` shrink labels). Mirror HL `app.css` mobile sidebar rules.
2. **Tables → stacked cards** at `≤660px`: `thead` hidden; each `tr` becomes a card (`display:block` /
   grid); label-per-cell via `data-label` attributes added in the row renderers (`ui/docker-ui.js`,
   `ui/processes-ui.js`) — **additive markup only**.
3. **Toolbars icon-only** (hide `<span>` labels); overflow into a popover.
4. **Console/terminal** full-screen sheet + reliable `FitAddon` re-fit on orientation change.
5. **≤410px** tightening pass (font/padding) and **≤900px** tablet hybrid if warranted.

## CSS architecture

- All responsive rules live in **`@media` blocks appended at the end of `styles.css`** (single-file by
  project convention — no new stylesheets). Group Phase 1 and Phase 2 under clear section banners.
- Use the existing design tokens (radius / type / transition scales). **No new hardcoded values.**
- Concrete source patterns to copy from:
  - `home-ledger/frontend/styles/app.css` — mobile sidebar → bottom-nav
  - `home-ledger/frontend/styles/filters.css` — toolbar collapse / icon-only
  - `home-ledger/frontend/styles/tables.css:146-228` — row → card transform
- Markup changes limited to: a hamburger button (Phase 1) and `data-label` attributes on table cells
  (Phase 2). **No layout restructuring, no logic/data-fetching changes.**

## Verification

1. Chrome DevTools device toolbar at **360×780**, **390×844**, and a tablet width; exercise each tab
   (containers, processes, disk, network, categories, settings), open a modal, open the console.
2. Confirm **desktop (>660px) is unchanged** — mobile rules are inside `@media` only.
3. Optionally drive with the Playwright MCP (`browser_resize` + `browser_navigate` to `:3232` +
   `browser_take_screenshot`) per breakpoint.
4. `npm test` → expect **27/27** (CSS-only; confirms the server boots). Manual visual check is the real
   gate.

## Risks / flags

- **App-shell `overflow:hidden`** (`styles.css:59`) is load-bearing for the desktop fixed layout — the
  mobile override must be scoped inside `@media` so desktop scroll behavior is preserved.
- **Stacked-card tables (Phase 2)** are the only part needing JS/markup (`data-label`); keep it additive
  and behind the breakpoint.
