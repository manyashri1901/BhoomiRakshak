// A royal-seal (rajmudra) style medallion — the hero's signature visual
// element. Entirely original: a beaded outer border, two concentric rings,
// and an eight-petal geometric rosette at center. No national emblem, no
// religious iconography, no reproduction of any historical dynasty's seal
// — general architectural/ornamental vocabulary only (the same rosette
// motif recurs independently across countless decorative traditions).

const PETAL_ANGLES = Array.from({ length: 8 }, (_, i) => i * 45);
const BEAD_ANGLES = Array.from({ length: 20 }, (_, i) => i * 18);

interface RoyalSealProps {
  className?: string;
}

export function RoyalSeal({ className }: RoyalSealProps) {
  return (
    <svg viewBox="0 0 120 120" className={className ?? "h-24 w-24"} aria-hidden="true">
      {/* beaded outer border */}
      {BEAD_ANGLES.map((angle) => {
        const rad = (angle * Math.PI) / 180;
        const cx = 60 + 55 * Math.cos(rad);
        const cy = 60 + 55 * Math.sin(rad);
        return <circle key={angle} cx={cx} cy={cy} r="1.6" fill="var(--color-camel)" />;
      })}

      {/* outer ring band */}
      <circle cx="60" cy="60" r="48" fill="none" stroke="var(--color-camel)" strokeWidth="3" />

      {/* inner disc */}
      <circle cx="60" cy="60" r="44" fill="var(--color-desert-sand)" opacity="0.5" />

      {/* thin inner ring */}
      <circle cx="60" cy="60" r="38" fill="none" stroke="var(--color-coffee)" strokeWidth="1" />

      {/* eight-petal rosette */}
      <g>
        {PETAL_ANGLES.map((angle) => (
          <ellipse
            key={angle}
            cx="60"
            cy="60"
            rx="6"
            ry="20"
            fill="var(--color-coffee)"
            opacity="0.85"
            transform={`rotate(${angle} 60 60) translate(0 -16)`}
          />
        ))}
        <circle cx="60" cy="60" r="7" fill="var(--color-camel)" />
        <circle cx="60" cy="60" r="3" fill="var(--color-apricot)" />
      </g>
    </svg>
  );
}
