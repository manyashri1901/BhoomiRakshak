import { useEffect, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, ClipboardCheck, Stamp, UserCheck } from "lucide-react";
import { Reveal } from "../components/ui/Reveal";
import { prefersReducedMotion } from "../components/ui/motion";
import { Button } from "../components/ui/Button";

const AUTO_ADVANCE_MS = 6000;

const STEPS = [
  {
    id: "landowner",
    label: "Landowner",
    icon: UserCheck,
    does: "Uploads a supporting document and signs the request with their own digital key.",
    checks: "Their identity certificate is valid and not revoked.",
  },
  {
    id: "village-officer",
    label: "Village Officer",
    icon: ClipboardCheck,
    does: "Reviews the details and documents, then adds their own signature.",
    checks: "The landowner's identity certificate is valid and not revoked.",
  },
  {
    id: "registrar",
    label: "Registrar",
    icon: Stamp,
    does: "Reviews the full history and signs the final record.",
    checks: "Both prior identity certificates are valid and not revoked.",
  },
];

function StepIllustration({ stepIndex }: { stepIndex: number }) {
  const step = STEPS[stepIndex];
  const Icon = step.icon;

  return (
    <div key={step.id} className="animate-fade-in-up flex flex-col items-center justify-center gap-3 rounded-xl border border-slate-200 bg-white p-6">
      <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-navy/10 text-navy">
        <Icon className="h-6 w-6" aria-hidden="true" />
      </div>
      <span className="text-sm font-medium text-slate-700">{step.label}</span>
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

const PKI_STRIP = [
  { title: "Authentication", description: "Proves who took the action, via their digital identity." },
  { title: "Integrity", description: "Proves the record hasn't changed since the moment it was signed." },
  { title: "Non-repudiation", description: "A signed action can't be plausibly denied by its signer." },
];

export function HowItWorksPage() {
  return (
    <div className="flex flex-col gap-16">
      <Reveal>
        <div>
          <h1 className="text-[28px] font-semibold text-slate-900 sm:text-[32px]">How it works</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-600">
            One request, three signatures — a real ordered approval chain, not a formality.
          </p>
        </div>
      </Reveal>

      <Reveal delay={60}>
        <Stepper />
      </Reveal>

      <Reveal delay={120}>
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
