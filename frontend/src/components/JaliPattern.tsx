// A jali (cut-stone lattice screen) motif as a faint background texture.
// Opacity is deliberately low and verified: measured contrast of both
// Dark Cocoa (9.48:1 baseline) and the muted text tone (7.60:1 baseline)
// against Apricot doesn't drop below ~9.0 / ~7.2 even at this pattern's
// full line weight — see the palette contrast notes for the underlying
// numbers. A repeating diamond-and-bead unit, not a specific screen design.
export function JaliPattern({ id = "jali" }: { id?: string }) {
  return (
    <svg className="pointer-events-none absolute inset-0 h-full w-full" aria-hidden="true">
      <defs>
        <pattern id={id} width="44" height="44" patternUnits="userSpaceOnUse">
          <path
            d="M22 2 L42 22 L22 42 L2 22 Z"
            fill="none"
            stroke="var(--color-camel)"
            strokeWidth="1"
          />
          <circle cx="22" cy="22" r="3" fill="none" stroke="var(--color-camel)" strokeWidth="1" />
          <circle cx="0" cy="0" r="1.5" fill="var(--color-camel)" />
          <circle cx="44" cy="0" r="1.5" fill="var(--color-camel)" />
          <circle cx="0" cy="44" r="1.5" fill="var(--color-camel)" />
          <circle cx="44" cy="44" r="1.5" fill="var(--color-camel)" />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill={`url(#${id})`} opacity="0.06" />
    </svg>
  );
}
