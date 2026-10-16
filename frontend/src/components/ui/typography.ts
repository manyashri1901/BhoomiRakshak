// Shared page-level style tokens for the public marketing pages (Home,
// About) — extracted from HomePage.tsx so About can match it exactly
// rather than re-declaring the same class strings.

// Heading treatment — navy color, tight tracking, clamp()-based fluid size.
export const H1 =
  "text-[clamp(43px,5vw,56px)] font-semibold leading-[1.03] tracking-[-0.035em] text-navy";
export const H2 =
  "text-[clamp(34px,4vw,46px)] font-semibold leading-[1.08] tracking-[-0.035em] text-navy";
export const SECTION_LABEL = "block text-sm font-bold uppercase tracking-[0.11em] text-teal";

// Reused per-section horizontal container — 1152px, matching the
// reference design (Layout's own shared chrome stays at its existing
// 1200px; this is a narrower, page-local content width within it).
export const CONTAINER = "mx-auto w-full max-w-288";

// 96px desktop / 72px tablet / 56px mobile, per spec.
export const SECTION_PADDING = "py-14 sm:py-18 lg:py-24";
