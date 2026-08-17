// A simple temple/palace niche-arch silhouette — general architectural
// vocabulary (a rounded horseshoe arch on two posts with a base line and
// an inset molding), not a reproduction of any specific structure. Purely
// a background outline: sized to frame the hero content from outside, not
// to run behind the text itself.
export function ArchFrame({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 672 300"
      preserveAspectRatio="none"
      className={className}
      aria-hidden="true"
      fill="none"
    >
      <path
        d="M60,300 L60,170 C60,80 160,20 336,20 C512,20 612,80 612,170 L612,300"
        stroke="var(--color-camel)"
        strokeWidth="2"
      />
      <path
        d="M86,300 L86,176 C86,98 180,46 336,46 C492,46 586,98 586,176 L586,300"
        stroke="var(--color-camel)"
        strokeWidth="1"
        opacity="0.6"
      />
      <line x1="34" y1="300" x2="638" y2="300" stroke="var(--color-camel)" strokeWidth="2" />
    </svg>
  );
}
