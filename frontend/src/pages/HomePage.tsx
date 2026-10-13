import { useState } from "react";
import { Link } from "react-router-dom";
import {
  ClipboardCheck,
  FileSignature,
  Hash,
  Link2,
  Stamp,
  UserCheck,
} from "lucide-react";

const FEATURES = [
  {
    icon: UserCheck,
    title: "Verified digital identity",
    description: "Every user holds a browser-generated RSA key pair and a CA-issued certificate.",
  },
  {
    icon: FileSignature,
    title: "Signed transactions",
    description: "Every registration, transfer, and update is signed by the acting party, not just recorded.",
  },
  {
    icon: Hash,
    title: "SHA-256 integrity",
    description: "Every supporting document's hash is independently recomputed from disk on demand.",
  },
  {
    icon: Link2,
    title: "Tamper-evident audit chain",
    description: "A hash-chained audit log makes any after-the-fact edit mathematically detectable.",
  },
];

const STEPS = [
  {
    icon: UserCheck,
    title: "Landowner submits and signs",
    description: "Uploads a supporting document and signs the transaction with their own private key.",
  },
  {
    icon: ClipboardCheck,
    title: "Village Officer verifies and signs",
    description: "Checks the landowner's signature and the document itself before co-signing.",
  },
  {
    icon: Stamp,
    title: "Registrar approves and signs",
    description: "Verifies the full signature chain, then finalizes the record.",
  },
];

// Animation-gated the same way the previous design was: decided once,
// synchronously, on first render — skipped for prefers-reduced-motion —
// so there's never a "hidden by default" state a slow/failed animation
// could get stuck in. Every element below is plain static content without
// the `.animate-fade-in-up` class.
let heroAnimationPlayed = false;

function shouldPlayHeroAnimation(): boolean {
  if (heroAnimationPlayed) return false;
  heroAnimationPlayed = true;
  if (typeof window === "undefined") return false;
  return !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function HomePage() {
  const [animate] = useState(shouldPlayHeroAnimation);
  const animateClass = animate ? "animate-fade-in-up" : "";

  return (
    <div className="flex flex-col gap-16">
      <section className="flex flex-col items-center gap-5 pt-8 pb-4 text-center">
        <h1 className={`max-w-3xl text-[32px] font-semibold leading-tight text-slate-900 sm:text-5xl ${animateClass}`}>
          Every land record, signed. Every signature, tamper-evident.
        </h1>
        <p className={`max-w-2xl text-base text-slate-600 ${animateClass}`}>
          A PKI-backed land registry where every transaction is cryptographically signed and every
          record stays independently verifiable, end to end.
        </p>
        <div className={`mt-2 flex flex-wrap items-center justify-center gap-3 ${animateClass}`}>
          <Link
            to="/register"
            className="rounded-lg bg-navy px-6 py-2.5 text-sm font-semibold text-white hover:bg-navy-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy"
          >
            Get started
          </Link>
          <a
            href="#how-it-works"
            className="rounded-lg border border-slate-300 px-6 py-2.5 text-sm font-semibold text-slate-700 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy"
          >
            How it works
          </a>
        </div>
      </section>

      <section>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {FEATURES.map(({ icon: Icon, title, description }) => (
            <div key={title} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal/10 text-teal">
                <Icon className="h-5 w-5" aria-hidden="true" />
              </div>
              <h3 className="mt-3 text-base font-semibold text-slate-900">{title}</h3>
              <p className="mt-1 text-sm text-slate-600">{description}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="how-it-works" className="scroll-mt-20">
        <h2 className="text-center text-xl font-semibold text-slate-900 sm:text-2xl">How it works</h2>
        <p className="mx-auto mt-2 max-w-xl text-center text-sm text-slate-600">
          One transaction, three signatures — a real ordered approval chain, not a formality.
        </p>

        <div className="mt-8 grid grid-cols-1 gap-6 md:grid-cols-3">
          {STEPS.map(({ icon: Icon, title, description }, i) => (
            <div key={title} className="relative rounded-xl border border-slate-200 bg-white p-6">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-navy/10 text-navy">
                <Icon className="h-5 w-5" aria-hidden="true" />
              </div>
              <div className="mt-3 text-xs font-semibold uppercase tracking-wide text-slate-400">
                Step {i + 1}
              </div>
              <h3 className="mt-1 text-base font-semibold text-slate-900">{title}</h3>
              <p className="mt-1 text-sm text-slate-600">{description}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
