import { useState } from "react";
import { Link } from "react-router-dom";
import { FileSignature, Hash, Link2, UserCheck } from "lucide-react";
import { Reveal } from "../components/ui/Reveal";
import { SecurityDetailsCard } from "../components/ui/SecurityDetailsCard";

const FEATURES = [
  {
    icon: UserCheck,
    title: "Verified digital identity",
    description: "Every user holds a browser-generated key pair and a CA-issued certificate.",
    detail: "RSA-2048 keys, generated and held client-side",
  },
  {
    icon: FileSignature,
    title: "Signed transactions",
    description: "Every registration, transfer, and update is signed by the acting party, not just recorded.",
    detail: "RSASSA-PKCS1-v1_5 signatures over a canonical payload",
  },
  {
    icon: Hash,
    title: "SHA-256 integrity",
    description: "Every supporting document's hash is independently recomputed from disk on demand.",
    detail: "Recomputed live — never trusts a cached flag",
  },
  {
    icon: Link2,
    title: "Tamper-evident audit chain",
    description: "A hash-chained audit log makes any after-the-fact edit mathematically detectable.",
    detail: "Each entry's hash commits to the one before it",
  },
];

// Fixed sample values for the hero's "Example" preview only — never real
// record data, labelled as such on screen.
const EXAMPLE_SIGNERS = [
  {
    name: "A. Kumar",
    roleLabel: "Landowner",
    fingerprint: "4f3c9a2e7d18b605c3a9f21e8d4b7c60a159e3d7c2b8f405a6e1d9c3b7f0825a",
    valid: true,
  },
];
const EXAMPLE_DOCUMENT_HASH = "9b1d4e7a2c650f38d9a4b6e1c7f3085a2d6b9e4c1f7a30586d2c9b4e7f10a358";

function BrowserFrame({ children }: { children: React.ReactNode }) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="flex items-center gap-1.5 border-b border-slate-200 bg-slate-50 px-3 py-2">
        <span className="h-2.5 w-2.5 rounded-full bg-slate-300" aria-hidden="true" />
        <span className="h-2.5 w-2.5 rounded-full bg-slate-300" aria-hidden="true" />
        <span className="h-2.5 w-2.5 rounded-full bg-slate-300" aria-hidden="true" />
        <span className="ml-2 rounded-md bg-white px-2 py-0.5 text-[11px] text-slate-400">bhoomirakshak.app</span>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function FeatureCard({
  icon: Icon,
  title,
  description,
  detail,
  revealed,
  onToggle,
}: (typeof FEATURES)[number] & { revealed: boolean; onToggle: () => void }) {
  return (
    <div
      onClick={onToggle}
      className="group cursor-pointer rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition-[transform,box-shadow] duration-200 hover:-translate-y-1 hover:shadow-md focus-within:-translate-y-1 focus-within:shadow-md"
    >
      <div className="flex items-center gap-2.5">
        <Icon className="h-5 w-5 text-navy" aria-hidden="true" />
        <h3 className="text-base font-semibold text-slate-900">{title}</h3>
      </div>
      <p className="mt-2 text-sm text-slate-600">{description}</p>
      <p
        className={`mt-2 overflow-hidden font-mono text-[11px] text-teal transition-all duration-200 ${
          revealed ? "max-h-6 opacity-100" : "max-h-0 opacity-0 group-hover:max-h-6 group-hover:opacity-100 group-focus-within:max-h-6 group-focus-within:opacity-100"
        }`}
      >
        {detail}
      </p>
    </div>
  );
}

export function HomePage() {
  const [tappedIndex, setTappedIndex] = useState<number | null>(null);

  return (
    <div className="flex flex-col gap-20">
      <section className="grid grid-cols-1 items-center gap-10 pt-8 lg:grid-cols-2 lg:gap-14">
        <Reveal>
          <h1 className="text-[32px] font-semibold leading-tight text-slate-900 sm:text-5xl">
            Every land record, signed. Every signature, tamper-evident.
          </h1>
          <p className="mt-4 max-w-xl text-base text-slate-600">
            A PKI-backed land registry where every transaction is cryptographically signed and every
            record stays independently verifiable, end to end.
          </p>
          <div className="mt-6 flex flex-wrap items-center gap-3">
            <Link
              to="/register"
              className="rounded-lg bg-navy px-6 py-2.5 text-sm font-semibold text-white hover:bg-navy-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy"
            >
              Get started
            </Link>
            <Link
              to="/how-it-works"
              className="rounded-lg border border-slate-300 px-6 py-2.5 text-sm font-semibold text-slate-700 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy"
            >
              See how it works
            </Link>
          </div>
        </Reveal>

        <Reveal delay={80}>
          <div className="mx-auto max-w-md">
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-400">Example</p>
            <BrowserFrame>
              <SecurityDetailsCard signers={EXAMPLE_SIGNERS} documentHash={EXAMPLE_DOCUMENT_HASH} />
            </BrowserFrame>
          </div>
        </Reveal>
      </section>

      <section>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {FEATURES.map((feature, i) => (
            <Reveal key={feature.title} delay={i * 80}>
              <FeatureCard
                {...feature}
                revealed={tappedIndex === i}
                onToggle={() => setTappedIndex((current) => (current === i ? null : i))}
              />
            </Reveal>
          ))}
        </div>
      </section>

      <Reveal>
        <section className="rounded-xl border border-slate-200 bg-white px-6 py-10 text-center">
          <h2 className="text-xl font-semibold text-slate-900 sm:text-2xl">Try the workflow</h2>
          <p className="mx-auto mt-2 max-w-md text-sm text-slate-600">
            Register an account, or walk through the three-signature approval chain first.
          </p>
          <div className="mt-5 flex flex-wrap items-center justify-center gap-3">
            <Link
              to="/register"
              className="rounded-lg bg-navy px-6 py-2.5 text-sm font-semibold text-white hover:bg-navy-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy"
            >
              Get started
            </Link>
            <Link
              to="/how-it-works"
              className="rounded-lg border border-slate-300 px-6 py-2.5 text-sm font-semibold text-slate-700 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy"
            >
              How it works
            </Link>
          </div>
        </section>
      </Reveal>
    </div>
  );
}
