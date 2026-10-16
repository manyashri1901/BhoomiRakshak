import { useEffect, useState } from "react";

// Thin teal bar reflecting how far down the current page the viewer has
// scrolled — direct visual feedback tied to the user's own scroll
// position, not an autoplaying animation, so it isn't gated behind
// prefers-reduced-motion the way the Reveal/route-fade effects are.
export function ScrollProgressBar() {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    function updateProgress() {
      const scrollable = document.documentElement.scrollHeight - window.innerHeight;
      setProgress(scrollable > 0 ? Math.min(1, Math.max(0, window.scrollY / scrollable)) : 0);
    }
    updateProgress();
    window.addEventListener("scroll", updateProgress, { passive: true });
    window.addEventListener("resize", updateProgress);
    return () => {
      window.removeEventListener("scroll", updateProgress);
      window.removeEventListener("resize", updateProgress);
    };
  }, []);

  return (
    <div className="fixed left-0 top-0 z-40 h-0.5 w-full bg-transparent" aria-hidden="true">
      <div className="h-full bg-teal transition-[width] duration-150 ease-out" style={{ width: `${progress * 100}%` }} />
    </div>
  );
}
