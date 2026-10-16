export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost" | "teal" | "white";

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary:
    "bg-navy text-white hover:bg-navy-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy",
  secondary:
    "border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy",
  danger:
    "border border-red-300 bg-white text-red-600 hover:bg-red-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-500",
  ghost:
    "text-slate-600 hover:bg-slate-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy",
  teal:
    "bg-teal text-white hover:bg-teal-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal",
  white:
    "bg-white text-navy hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white",
};

// Shared by <Button> (a real <button>) and plain navigation <Link>s (e.g.
// the home page's CTAs, which must navigate rather than submit/act) so
// both render identical visual styling from one source.
export function buttonVariantClasses(variant: ButtonVariant = "primary", className = "") {
  return `inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${VARIANT_CLASSES[variant]} ${className}`;
}
