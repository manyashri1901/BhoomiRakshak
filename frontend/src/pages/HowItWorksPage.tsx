import { useEffect, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, ClipboardCheck, RotateCcw, Stamp, UserCheck } from "lucide-react";
import { Reveal } from "../components/ui/Reveal";
import { prefersReducedMotion } from "../components/ui/motion";
import { Banner } from "../components/ui/Banner";
import { Button } from "../components/ui/Button";
import { CopyButton } from "../components/ui/CopyButton";

const AUTO_ADVANCE_MS = 6000;

const STEPS = [
  {
    id: "landowner",
    label: "Landowner",
    icon: UserCheck,
    does: "Uploads a supporting document and signs the transaction with their own private key.",
    signs: "A canonical payload: transaction type, land record, and the document's SHA-256 hash.",
    checks: "Their own certificate is valid (not expired or revoked) before the signature is accepted.",
  },
  {
    id: "village-officer",
    label: "Village Officer",
    icon: ClipboardCheck,
    does: "Reviews the landowner's document and signature, then co-signs to approve it.",
    signs: "The same payload, now chained to the landowner's signature.",
    checks: "The landowner's signature verifies, their certificate is still valid, and the document hash still matches the file on disk.",
  },
  {
    id: "registrar",
    label: "Registrar",
    icon: Stamp,
    does: "Verifies the full two-signature chain, then finalizes the record.",
    signs: "The complete payload, now chained to both prior signatures.",
    checks: "Both prior signatures and certificates, end to end, before the land record is updated.",
  },
];

function StepIllustration({ stepIndex }: { stepIndex: number }) {
  const step = STEPS[stepIndex];
  const Icon = step.icon;
  // A short, fixed, illustrative hex string per step — not a real hash of
  // anything, just a visual cue that something cryptographic changes hands
  // at each stage.
  const sample = ["7f3a9c2e1b6d8504", "c58b1f4d9a73e602", "2d9f6b1e4a7c83f0"][stepIndex];

  return (
    <div key={step.id} className="animate-fade-in-up flex flex-col items-center gap-3 rounded-xl border border-slate-200 bg-white p-6">
      <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-navy/10 text-navy">
        <Icon className="h-6 w-6" aria-hidden="true" />
      </div>
      <div className="font-mono text-xs text-teal">sig:{sample}…</div>
    </div>
  );
}

function Stepper() {
  const [activeIndex, setActiveIndex] = useState(0);
  const [interacted, setInteracted] = useState(false);
  const [paused, setPaused] = useState(false);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  useEffect(() => {
    if (interacted || paused || prefersReducedMotion()) return;
    const timer = setInterval(() => {
      setActiveIndex((i) => (i + 1) % STEPS.length);
    }, AUTO_ADVANCE_MS);
    return () => clearInterval(timer);
  }, [interacted, paused]);

  function select(index: number, focusTab = false) {
    setActiveIndex(index);
    setInteracted(true);
    if (focusTab) tabRefs.current[index]?.focus();
  }

  function handleKeyDown(event: React.KeyboardEvent) {
    if (event.key === "ArrowRight") {
      event.preventDefault();
      select((activeIndex + 1) % STEPS.length, true);
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      select((activeIndex - 1 + STEPS.length) % STEPS.length, true);
    }
  }

  const active = STEPS[activeIndex];

  return (
    <div
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)}
      onBlur={() => setPaused(false)}
    >
      <div role="tablist" aria-label="Approval steps" onKeyDown={handleKeyDown} className="flex gap-2">
        {STEPS.map((step, i) => (
          <button
            key={step.id}
            ref={(el) => {
              tabRefs.current[i] = el;
            }}
            role="tab"
            id={`step-tab-${step.id}`}
            aria-selected={i === activeIndex}
            aria-controls={`step-panel-${step.id}`}
            tabIndex={i === activeIndex ? 0 : -1}
            onClick={() => select(i)}
            className={`flex-1 rounded-lg border px-3 py-2.5 text-left text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy ${
              i === activeIndex ? "border-navy bg-navy text-white" : "border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
            }`}
          >
            <span className="block text-xs font-semibold uppercase tracking-wide opacity-70">Step {i + 1}</span>
            {step.label}
          </button>
        ))}
      </div>

      <div className="mt-4 grid grid-cols-1 gap-6 lg:grid-cols-[1fr_200px]">
        <div
          key={active.id}
          id={`step-panel-${active.id}`}
          role="tabpanel"
          aria-labelledby={`step-tab-${active.id}`}
          tabIndex={0}
          className="animate-fade-in-up rounded-xl border border-slate-200 bg-white p-5"
        >
          <dl className="flex flex-col gap-4 text-sm">
            <div>
              <dt className="font-semibold text-slate-900">What they do</dt>
              <dd className="mt-1 text-slate-600">{active.does}</dd>
            </div>
            <div>
              <dt className="font-semibold text-slate-900">What they sign</dt>
              <dd className="mt-1 text-slate-600">{active.signs}</dd>
            </div>
            <div>
              <dt className="font-semibold text-slate-900">What's checked</dt>
              <dd className="mt-1 text-slate-600">{active.checks}</dd>
            </div>
          </dl>
        </div>

        <StepIllustration stepIndex={activeIndex} />
      </div>

      <div className="mt-4 flex items-center justify-between">
        <Button variant="secondary" onClick={() => select((activeIndex - 1 + STEPS.length) % STEPS.length)} icon={<ChevronLeft className="h-4 w-4" aria-hidden="true" />}>
          Previous
        </Button>
        <Button variant="secondary" onClick={() => select((activeIndex + 1) % STEPS.length)} icon={<ChevronRight className="h-4 w-4" aria-hidden="true" />}>
          Next
        </Button>
      </div>
    </div>
  );
}

const SAMPLE_TEXT = "Plot 42, Survey 118/3, Owner: A. Kumar, Area: 1200 sq m";

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function TamperDemo() {
  const [text, setText] = useState(SAMPLE_TEXT);
  const [originalHash, setOriginalHash] = useState<string | null>(null);
  const [currentHash, setCurrentHash] = useState<string | null>(null);

  // Computed once, from the sample text as it was when this page loaded —
  // "the fingerprint of the original saved on load" — independent of
  // anything the user types afterward.
  useEffect(() => {
    sha256Hex(SAMPLE_TEXT).then(setOriginalHash);
  }, []);

  useEffect(() => {
    let cancelled = false;
    sha256Hex(text).then((hash) => {
      if (!cancelled) setCurrentHash(hash);
    });
    return () => {
      cancelled = true;
    };
  }, [text]);

  const matches = originalHash !== null && currentHash !== null && currentHash === originalHash;

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-400">Demo — sample text, not a real record</p>
      <label className="mt-3 flex flex-col gap-1.5">
        <span className="text-sm font-medium text-slate-700">Record text</span>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={3}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-sm text-slate-900 outline-none transition-colors focus:border-teal focus:ring-2 focus:ring-teal/30"
        />
      </label>

      <div className="mt-3 flex flex-col gap-2 text-sm">
        <div className="flex items-center gap-2">
          <span className="w-32 shrink-0 text-slate-500">Original hash</span>
          <span className="truncate font-mono text-xs text-slate-700">{originalHash ?? "computing…"}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-32 shrink-0 text-slate-500">Current hash</span>
          <span className="truncate font-mono text-xs text-slate-700">{currentHash ?? "computing…"}</span>
          {currentHash && <CopyButton value={currentHash} label="Copy current hash" />}
        </div>
      </div>

      <div className="mt-3">
        {originalHash === null || currentHash === null ? null : matches ? (
          <Banner variant="success">Matches the original.</Banner>
        ) : (
          <Banner variant="danger">Hash mismatch — tampering detected.</Banner>
        )}
      </div>

      <div className="mt-3">
        <Button variant="secondary" onClick={() => setText(SAMPLE_TEXT)} icon={<RotateCcw className="h-4 w-4" aria-hidden="true" />}>
          Reset
        </Button>
      </div>
    </div>
  );
}

const PKI_STRIP = [
  { title: "Authentication", description: "Proves who signed, via their CA-issued certificate." },
  { title: "Integrity", description: "Proves the data hasn't changed since the moment it was signed." },
  { title: "Non-repudiation", description: "A valid signature can't be plausibly denied by its signer." },
];

export function HowItWorksPage() {
  return (
    <div className="flex flex-col gap-16">
      <Reveal>
        <div>
          <h1 className="text-[28px] font-semibold text-slate-900 sm:text-[32px]">How it works</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-600">
            One transaction, three signatures — a real ordered approval chain, not a formality.
          </p>
        </div>
      </Reveal>

      <Reveal delay={60}>
        <Stepper />
      </Reveal>

      <Reveal delay={120}>
        <div>
          <h2 className="text-lg font-semibold text-slate-900">Try it: tamper detection</h2>
          <p className="mt-1 text-sm text-slate-600">
            Edit the text below and watch the hash change — this is the same SHA-256 check the app
            runs on real documents.
          </p>
          <div className="mt-4">
            <TamperDemo />
          </div>
        </div>
      </Reveal>

      <Reveal delay={180}>
        <div>
          <h2 className="text-lg font-semibold text-slate-900">What PKI gives you</h2>
          <div className="mt-4 grid grid-cols-1 divide-y divide-slate-200 rounded-xl border border-slate-200 bg-white sm:grid-cols-3 sm:divide-x sm:divide-y-0">
            {PKI_STRIP.map(({ title, description }) => (
              <div key={title} className="p-5">
                <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
                <p className="mt-1 text-sm text-slate-600">{description}</p>
              </div>
            ))}
          </div>
        </div>
      </Reveal>
    </div>
  );
}
