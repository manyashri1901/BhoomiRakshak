// A carved-lintel-style divider — line, diamond ornament, line — standing
// in for a plain <hr> between the hero and the explainer section.
export function CarvedDivider() {
  return (
    <div role="separator" aria-hidden="true" className="flex items-center justify-center gap-4">
      <span className="h-px w-20 bg-camel sm:w-40" />
      <span className="h-2.5 w-2.5 rotate-45 border border-camel" />
      <span className="h-px w-20 bg-camel sm:w-40" />
    </div>
  );
}
