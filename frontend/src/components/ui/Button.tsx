import { Loader2 } from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { buttonVariantClasses, type ButtonVariant } from "./buttonVariants";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  loading?: boolean;
  icon?: ReactNode;
}

export function Button({
  variant = "primary",
  loading = false,
  icon,
  disabled,
  className = "",
  children,
  ...rest
}: ButtonProps) {
  return (
    <button disabled={disabled || loading} className={buttonVariantClasses(variant, className)} {...rest}>
      {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : icon}
      {children}
    </button>
  );
}
