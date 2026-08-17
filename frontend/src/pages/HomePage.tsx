import { useState } from "react";
import { Link } from "react-router-dom";
import { RoyalSeal } from "../components/RoyalSeal";
import { ArchFrame } from "../components/ArchFrame";
import { JaliPattern } from "../components/JaliPattern";
import { CarvedDivider } from "../components/CarvedDivider";

const STEPS = [
  {
    number: "01",
    title: "Landowner submits",
    description:
      "The landowner uploads a supporting document and signs the transaction with their own private key.",
  },
  {
    number: "02",
    title: "Village Officer verifies",
    description:
      "The Village Officer checks the landowner's signature and the document itself before co-signing.",
  },
  {
    number: "03",
    title: "Registrar approves and finalizes",
    description:
      "The Registrar verifies the full signature chain, then finalizes the record — updating ownership where it applies.",
  },
];

// One word per staggered <span> — the ink-settling headline effect. Each
// entry's delay is baked in here (not computed from index*N) so the two
// lines can have their own pacing rather than one flat cadence.
const HEADLINE_LINE_1 = [
  { text: "Every", delay: 100 },
  { text: "land", delay: 160 },
  { text: "record,", delay: 220 },
  { text: "signed.", delay: 280 },
];
const HEADLINE_LINE_2 = [
  { text: "Every", delay: 340 },
  { text: "signature,", delay: 400 },
  { text: "verified.", delay: 460 },
];

// Module-level, not component state: resets only on an actual page
// reload (fresh module evaluation), and stays true across client-side
// navigation back to "/" within the same load — e.g. after logging out.
let heroAnimationPlayed = false;

function shouldPlayHeroAnimation(): boolean {
  if (heroAnimationPlayed) return false;
  heroAnimationPlayed = true;
  if (typeof window === "undefined") return false;
  return !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function HomePage() {
  // Lazy initializer runs synchronously during the first render, before
  // paint — so there's no flash between "static" and "about to animate"
  // states, and no useEffect needed to decide this.
  const [animate] = useState(shouldPlayHeroAnimation);

  return (
    <div className={`flex flex-col gap-14 ${animate ? "hero-animate" : ""}`}>
      <section className="relative overflow-hidden">
        <div className="hero-bg-layer pointer-events-none absolute inset-0">
          <JaliPattern />
          {/* vignette — an old document catching the light */}
          <div
            className="absolute inset-0"
            style={{
              background:
                "radial-gradient(ellipse at center, transparent 55%, rgba(70,32,18,0.10) 100%)",
            }}
          />
        </div>

        <div className="relative z-10 flex flex-col items-center gap-5 pt-6 pb-4 text-center">
          {/* The arch frames only the seal + headline — sized to that
              block specifically, not the sub-line/caption/CTAs below it,
              so its curve never runs behind body text. */}
          <div className="relative flex w-full max-w-2xl flex-col items-center pt-8 pb-10">
            <ArchFrame className="pointer-events-none absolute inset-0 -z-10 h-full w-full" />
            <RoyalSeal className="hero-seal h-24 w-24" />
            <h1 className="mt-5 w-full max-w-2xl font-serif text-2xl font-semibold text-ink sm:text-4xl md:text-5xl">
              {HEADLINE_LINE_1.map(({ text, delay }, i) => (
                <span key={text + delay}>
                  {i > 0 && " "}
                  <span className="hero-word" style={{ animationDelay: `${delay}ms` }}>
                    {text}
                  </span>
                </span>
              ))}
              <br className="hidden sm:block" />
              {" "}
              {HEADLINE_LINE_2.map(({ text, delay }, i) => (
                <span key={text + delay}>
                  {i > 0 && " "}
                  <span className="hero-word" style={{ animationDelay: `${delay}ms` }}>
                    {text}
                  </span>
                </span>
              ))}
            </h1>
          </div>

          <p className="hero-stagger hero-stagger-1 max-w-2xl text-base text-ink">
            Each user holds a PKI-backed digital identity, every transaction is digitally signed,
            and the full history stays tamper-evident — built to complement systems like DILRMP,
            not replace them.
          </p>

          <p className="hero-stagger hero-stagger-2 max-w-xl text-sm italic text-muted">
            In the spirit of the sealed land grants of old — verified, permanent, and true.
          </p>

          <div className="hero-stagger hero-stagger-4 mt-3 flex flex-wrap items-center justify-center gap-4">
            <Link
              to="/login"
              className="rounded-md bg-coffee px-6 py-2.5 text-sm font-semibold text-apricot hover:bg-coffee-hover focus-visible:outline-2 focus-visible:-outline-offset-4 focus-visible:outline-apricot"
            >
              Log In
            </Link>
            <Link
              to="/register"
              className="rounded-md border border-camel px-6 py-2.5 text-sm font-semibold text-ink hover:bg-surface focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-coffee"
            >
              Register
            </Link>
          </div>
        </div>
      </section>

      <CarvedDivider />

      <section className="hero-stagger hero-stagger-3">
        <h2 className="text-center font-serif text-2xl font-semibold text-ink">How it works</h2>
        <p className="mx-auto mt-2 max-w-xl text-center text-sm text-muted">
          One transaction, three signatures — a real ordered approval chain, not a formality.
        </p>

        <div className="mt-10 grid grid-cols-1 gap-6 md:grid-cols-3">
          {STEPS.map((step) => (
            <div
              key={step.number}
              className="rounded-lg border border-border-subtle bg-surface p-6"
            >
              <div className="font-serif text-3xl font-semibold text-ink">{step.number}</div>
              <div className="mt-2 h-px w-10 bg-camel" aria-hidden="true" />
              <h3 className="mt-3 font-serif text-lg font-semibold text-ink">{step.title}</h3>
              <p className="mt-1 text-sm text-muted">{step.description}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
