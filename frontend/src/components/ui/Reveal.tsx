import { useEffect, useRef, useState, type ReactNode } from "react";
import { prefersReducedMotion } from "./motion";

interface RevealProps {
  children: ReactNode;
  /** Stagger delay in ms, applied via inline transition-delay. */
  delay?: number;
  className?: string;
}

// Fades + slides a section up by 16px once, the first time it enters the
// viewport — IntersectionObserver-based, no scroll-event polling. Content
// is never hidden outside of JS running (the base state has no opacity-0
// without a browser that supports IntersectionObserver), and
// prefers-reduced-motion skips the effect entirely, showing content
// immediately in its final position.
export function Reveal({ children, delay = 0, className = "" }: RevealProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(() => prefersReducedMotion());

  useEffect(() => {
    if (visible) return; // already showing (reduced motion, or revealed already)
    const node = ref.current;
    if (!node || typeof IntersectionObserver === "undefined") {
      setVisible(true);
      return;
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.15 },
    );
    observer.observe(node);
    return () => observer.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div
      ref={ref}
      className={`transition-[opacity,transform] duration-500 ease-out ${
        visible ? "translate-y-0 opacity-100" : "translate-y-4 opacity-0"
      } ${className}`}
      style={{ transitionDelay: visible ? `${delay}ms` : "0ms" }}
    >
      {children}
    </div>
  );
}
