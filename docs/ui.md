# UI design

The frontend is a minimalist flat design, trust-first (government/fintech
feel) rather than decorative — no glassmorphism, neumorphism, or gradients
on data. Light `backdrop-blur` is used only on the sticky navbar and modal
overlays.

**Principles**:

- Large clear hierarchy (one type scale, Inter), generous white space, few
  colors, consistent 8px spacing.
- Solid white cards with a thin `slate-200` border and a subtle shadow
  instead of heavier elevation effects.
- Interactive elements always show a visible focus ring.
- Animation is subtle and one-shot (sections fade/slide up once on
  entering the viewport, a thin scroll-progress bar, a brief fade on
  route change) and is skipped entirely under `prefers-reduced-motion`.

## Color tokens

Defined once in `frontend/src/index.css` as Tailwind `@theme` variables so
no component hard-codes a hex value:

| Token | Value | Use |
|---|---|---|
| `--color-navy` | `#0F2A4A` | Primary — headings, primary buttons, active nav state |
| `--color-teal` | `#0D9488` | Accent, used sparingly — links in illustrative/technical spots, scroll-progress bar |

Everything else (neutrals, status colors, white surfaces) uses Tailwind's
built-in `slate`/`green`/`amber`/`red`/`white` palette directly, since that
palette is itself already a defined token set rather than ad hoc hex values.

## Routes

| Path | Page | Auth |
|---|---|---|
| `/` | Home (hero, features, CTA band) | Public |
| `/about` | About — what the project is, the problem, the approach, scope and limits | Public |
| `/login`, `/register` | Auth | Public |
| `/how-it-works` | Interactive stepper, tamper-detection walkthrough, PKI strip | Logged in |
| `/verify` | Independent transaction verification | Logged in |
| `/landowner`, `/village-officer`, `/registrar`, `/admin` | Role dashboards | Logged in, role-gated |
| `/land-records`, `/land-records/:id`, `/certificates` | Registry & certificate lookup | Logged in |

Logged-in users keep the role sidebar and a short attribution footer. The
public navbar (Home / About / Login / Get started) and a single-line
attribution footer only render when signed out.
