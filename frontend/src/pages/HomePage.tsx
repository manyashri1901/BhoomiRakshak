import { Link } from "react-router-dom";
import {
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  FileText,
  Info,
  KeyRound,
  Lock,
  Stamp,
  UserCheck,
} from "lucide-react";
import { Reveal } from "../components/ui/Reveal";
import { Card } from "../components/Card";
import { buttonVariantClasses } from "../components/ui/buttonVariants";

// Shared heading treatment — matches the reference design's h1/h2 exactly
// (navy color, tight tracking, clamp()-based fluid size) without repeating
// the class string at every call site.
const H1 =
  "text-[clamp(43px,5vw,56px)] font-semibold leading-[1.03] tracking-[-0.035em] text-navy";
const H2 =
  "text-[clamp(34px,4vw,46px)] font-semibold leading-[1.08] tracking-[-0.035em] text-navy";
const SECTION_LABEL = "block text-sm font-bold uppercase tracking-[0.11em] text-teal";
// Reused per-section horizontal container — 1152px, matching the
// reference design (Layout's own shared chrome stays at its existing
// 1200px; this is a narrower, page-local content width within it).
const CONTAINER = "mx-auto w-full max-w-288";
// 96px desktop / 72px tablet / 56px mobile, per spec.
const SECTION_PADDING = "py-14 sm:py-18 lg:py-24";

const TRUST_POINTS = ["Signed by verified identities", "Hash-checked documents", "Tamper-evident audit log"];

// Fixed sample data for the hero's record panel only — never a real
// record. Honesty fix: a visible "Sample" pill in the header, plus a
// muted caption under the panel, so it can never be mistaken for a live
// result (names and plot data kept as in the reference design).
const TIMELINE: [string, string][] = [
  ["Landowner submitted and signed", "A. Kumar"],
  ["Village Officer verified and signed", "R. Singh"],
  ["Registrar approved and signed", "K. Patel · record sealed"],
];

function RecordPanel() {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 p-6">
        <div className="flex items-start justify-between gap-3">
          <div>
            <span className="block text-sm font-semibold uppercase tracking-widest text-teal">
              Land record · Demo data
            </span>
            <h3 className="mt-2 text-xl font-semibold tracking-tight text-navy">Plot 42, Survey 118/3</h3>
            <p className="mt-1 text-sm text-slate-600">Ownership transfer · 1,200 sq m</p>
          </div>
          <span className="shrink-0 rounded-full bg-slate-100 px-2.5 py-1 text-sm font-medium text-slate-500">
            Sample
          </span>
        </div>
        <span className="mt-4 inline-flex items-center gap-1.5 rounded-md bg-success-bg px-2.5 py-1 text-sm font-semibold text-success">
          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
          All signatures valid
        </span>
      </div>

      <div className="flex flex-col gap-0 px-6 py-5">
        {TIMELINE.map(([title, person], index) => (
          <div key={title} className="relative grid grid-cols-[22px_1fr] gap-3 pb-6 last:pb-0">
            <span className="z-10 flex h-5.5 w-5.5 items-center justify-center rounded-full bg-teal text-white">
              <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
            </span>
            {index < TIMELINE.length - 1 && (
              <span className="absolute left-2.5 top-5.5 bottom-0 w-px bg-teal/30" aria-hidden="true" />
            )}
            <div>
              <strong className="block text-sm font-semibold tracking-tight text-navy">{title}</strong>
              <small className="text-sm text-slate-500">{person}</small>
            </div>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-2 border-t border-slate-200 bg-slate-50 px-6 py-3 text-sm font-semibold text-success">
        <Lock className="h-3.5 w-3.5" aria-hidden="true" />
        Audit chain valid · no broken links
      </div>
    </div>
  );
}

const BUILT_WITH = ["Node.js", "PostgreSQL", "React", "Web Crypto API", "RSA-2048 · SHA-256", "Prisma"];

const PROBLEMS: [string, string, string][] = [
  [
    "01",
    "Forged or altered documents",
    "Scanned records can be edited without leaving a reliable trace of what changed.",
  ],
  [
    "02",
    "Double sale of one plot",
    "Disconnected workflows make conflicting ownership claims difficult to catch early.",
  ],
  [
    "03",
    "No proof of who approved",
    "A name in a database is not cryptographic proof that an official took the action.",
  ],
];

const ROLES: { title: string; description: string; icon: typeof UserCheck }[] = [
  {
    title: "Landowner",
    description: "Creates the request, uploads ownership documents and signs with their private key.",
    icon: UserCheck,
  },
  {
    title: "Village Officer",
    description: "Verifies the submitted details and documents, then adds a chained signature.",
    icon: ClipboardCheck,
  },
  {
    title: "Registrar",
    description: "Reviews the complete signed history, gives final approval and seals the record.",
    icon: Stamp,
  },
];

const SECURITY: { title: string; description: string; how: string; icon: typeof UserCheck }[] = [
  {
    title: "Verified digital identity",
    description: "Each participant receives a role-bound digital certificate.",
    how: "2048-bit RSA keys generated in your browser · CA-issued certificate",
    icon: UserCheck,
  },
  {
    title: "Signed transactions",
    description: "Each approval can be traced to a verified identity and exact request.",
    how: "RSASSA-PKCS1-v1_5 signatures · single-use nonces",
    icon: KeyRound,
  },
  {
    title: "SHA-256 integrity",
    description: "Uploaded documents are fingerprinted, so a one-character change is visible.",
    how: "Document hash recomputed and compared to the recorded value",
    icon: FileText,
  },
  {
    title: "Tamper-evident audit chain",
    description: "Every workflow event is linked to the history that came before it.",
    how: "Each log entry includes the hash of the previous one",
    icon: Lock,
  },
];

const PROTECTS_AGAINST = [
  "Forged signatures and replayed requests",
  "Revoked or expired certificates",
  "Wrong-role approvals and skipped stages",
  "Double sale of the same plot",
  "Tampered documents and audit rows",
];

// Honesty fix: kept exactly as specified, not softened.
const DOES_NOT_CLAIM = [
  "Not a legal registry",
  "No government-recognised certificate authority yet",
  "Tamper-evident, not tamper-proof",
  "A forgotten password means a lost signing key",
];

export function HomePage() {
  return (
    <div className="flex flex-col">
      <section className="pt-8 pb-14 sm:pb-18 lg:pb-24">
        <div className={`${CONTAINER} grid grid-cols-1 items-center gap-10 lg:grid-cols-2 lg:gap-16`}>
          <Reveal>
            <span className="mb-6 inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm font-semibold text-navy">
              <span className="h-1.5 w-1.5 rounded-full bg-teal" aria-hidden="true" />
              Open prototype · PKI-based land records
            </span>
            <h1 className={`${H1} max-w-xl`}>Land records you can verify, not just trust.</h1>
            <p className="mt-5 max-w-lg text-base text-slate-600">
              Every registration and approval is digitally signed by a verified identity. Every
              document is fingerprinted. Change anything afterwards and the system shows it.
            </p>
            <div className="mt-7 flex flex-wrap items-center gap-3">
              <Link to="/register" className={buttonVariantClasses("teal", "px-6 py-3")}>
                Get started
              </Link>
              <Link to="/how-it-works" className={buttonVariantClasses("secondary", "px-6 py-3")}>
                See how it works
              </Link>
            </div>
            <div className="mt-7 flex flex-wrap gap-5">
              {TRUST_POINTS.map((text) => (
                <span key={text} className="flex items-center gap-1.5 text-sm text-slate-600">
                  <CheckCircle2 className="h-4 w-4 text-teal" aria-hidden="true" />
                  {text}
                </span>
              ))}
            </div>
          </Reveal>

          <Reveal delay={80}>
            <div className="mx-auto max-w-md">
              <RecordPanel />
              <p className="mt-3 text-center text-sm text-slate-500">
                Illustrative sample. Real results appear after you sign in.
              </p>
            </div>
          </Reveal>
        </div>
      </section>

      <section className="border-y border-slate-200">
        <div className={`${CONTAINER} flex min-h-20 flex-wrap items-center justify-between gap-x-6 gap-y-3 py-4`}>
          <span className="text-sm font-semibold uppercase tracking-widest text-slate-400">Built with</span>
          {BUILT_WITH.map((item) => (
            <strong key={item} className="text-sm font-semibold text-slate-600">
              {item}
            </strong>
          ))}
        </div>
      </section>

      <section className={`${SECTION_PADDING} bg-slate-50`}>
        <div className={CONTAINER}>
          <Reveal>
            <span className={SECTION_LABEL}>The problem</span>
            <h2 className={H2}>Digitised records still leave gaps</h2>
            <p className="mb-12 mt-4 max-w-xl text-base text-slate-600">
              Moving a record online improves access. It does not, by itself, prove who authorised
              it or whether it changed later.
            </p>
          </Reveal>
          <div className="grid grid-cols-1 gap-7 md:grid-cols-3">
            {PROBLEMS.map(([number, title, body], i) => (
              <Reveal key={number} delay={i * 80}>
                <div className="border-t-2 border-navy pt-5">
                  <span className="text-sm font-bold text-teal">{number}</span>
                  <h3 className="mt-5 text-lg font-semibold tracking-tight text-navy">{title}</h3>
                  <p className="mt-2.5 text-sm text-slate-600">{body}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      <section className={SECTION_PADDING}>
        <div className={CONTAINER}>
          <Reveal className="mb-10 flex flex-wrap items-end justify-between gap-5">
            <div>
              <span className={SECTION_LABEL}>How it works</span>
              <h2 className={`${H2} mb-0`}>Three roles. Three signatures.</h2>
            </div>
            <Link
              to="/how-it-works"
              className={buttonVariantClasses("ghost", "px-0! text-teal! hover:bg-transparent! hover:text-teal-hover!")}
            >
              Explore the workflow <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </Link>
          </Reveal>
          <div className="grid grid-cols-1 gap-7 md:grid-cols-3">
            {ROLES.map(({ title, description, icon: Icon }, i) => (
              <Reveal key={title} delay={i * 80}>
                <Card className="relative min-h-65">
                  <span className="float-right font-mono text-sm text-slate-400">0{i + 1}</span>
                  <div className="mb-7 flex h-12 w-12 items-center justify-center rounded-lg bg-teal/10 text-teal">
                    <Icon className="h-6 w-6" aria-hidden="true" />
                  </div>
                  <h3 className="text-lg font-semibold tracking-tight text-navy">{title}</h3>
                  <p className="mt-2.5 text-sm text-slate-600">{description}</p>
                  {i < ROLES.length - 1 && (
                    <span
                      className="absolute top-1/2 -right-8.25 z-10 hidden h-8.5 w-11 -translate-y-1/2 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-400 md:flex"
                      aria-hidden="true"
                    >
                      <ArrowRight className="h-4 w-4" />
                    </span>
                  )}
                </Card>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      <section className={`${SECTION_PADDING} bg-slate-50`}>
        <div className={CONTAINER}>
          <Reveal>
            <span className={SECTION_LABEL}>What it secures</span>
            <h2 className={H2}>
              Every action is signed.
              <br />
              Every record is checkable.
            </h2>
          </Reveal>
          <div className="mt-11 grid grid-cols-1 gap-5 md:grid-cols-2">
            {SECURITY.map(({ title, description, how, icon: Icon }, i) => (
              <Reveal key={title} delay={i * 80}>
                <div className="grid h-full grid-cols-[42px_1fr] gap-4 rounded-xl border border-slate-200 bg-white p-7 transition-colors hover:border-teal">
                  <Icon className="mt-0.5 h-6 w-6 text-teal" aria-hidden="true" />
                  <div>
                    <h3 className="text-lg font-semibold tracking-tight text-navy">{title}</h3>
                    <p className="mt-2.5 mb-6 text-sm text-slate-600">{description}</p>
                    <p className="border-t border-slate-200 pt-4 text-sm leading-relaxed text-slate-500">
                      <b className="mr-2 font-semibold uppercase tracking-widest text-teal">How</b>
                      {how}
                    </p>
                  </div>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      <section className={SECTION_PADDING}>
        <div className={CONTAINER}>
          <Reveal>
            <span className={SECTION_LABEL}>Honest by design</span>
            <h2 className={H2}>Built with the limits in plain sight</h2>
          </Reveal>
          <div className="mt-11 grid grid-cols-1 gap-6 md:grid-cols-2">
            <Reveal>
              <div className="rounded-xl border border-slate-200 p-8">
                <h3 className="mb-5 border-b border-slate-200 pb-5 text-lg font-semibold tracking-tight text-navy">
                  What it protects against
                </h3>
                {PROTECTS_AGAINST.map((item) => (
                  <p key={item} className="mb-3.5 flex items-start gap-2.5 text-sm text-slate-700 last:mb-0">
                    <CheckCircle2 className="mt-0.5 h-4.5 w-4.5 shrink-0 text-success" aria-hidden="true" />
                    {item}
                  </p>
                ))}
              </div>
            </Reveal>
            <Reveal delay={80}>
              <div className="rounded-xl border border-slate-200 p-8">
                <h3 className="mb-5 border-b border-slate-200 pb-5 text-lg font-semibold tracking-tight text-navy">
                  What it does not claim
                </h3>
                {DOES_NOT_CLAIM.map((item) => (
                  <p key={item} className="mb-3.5 flex items-start gap-2.5 text-sm text-slate-700 last:mb-0">
                    <Info className="mt-0.5 h-4.5 w-4.5 shrink-0 text-warning" aria-hidden="true" />
                    {item}
                  </p>
                ))}
              </div>
            </Reveal>
          </div>
        </div>
      </section>

      <section className="px-4 pb-14 sm:px-0 sm:pb-18 lg:pb-24">
        <Reveal className={CONTAINER}>
          <div className="flex flex-col items-start gap-8 rounded-2xl bg-navy p-8 text-white sm:p-14 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <span className="block text-sm font-bold uppercase tracking-[0.11em] text-teal/70">
                Interactive prototype
              </span>
              <h2 className="mt-4 text-[clamp(28px,3.5vw,38px)] font-semibold leading-tight tracking-[-0.035em] text-white">
                See the workflow end to end
              </h2>
              <p className="mt-2 max-w-md text-sm text-slate-300">
                Create a demo identity, submit a record and see how each signature builds trust.
              </p>
            </div>
            <div className="flex shrink-0 flex-wrap gap-3">
              <Link to="/register" className={buttonVariantClasses("white", "px-6 py-3")}>
                Get started
              </Link>
              <Link
                to="/how-it-works"
                className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/30 px-6 py-3 text-sm font-semibold text-white transition-colors hover:bg-white/10 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
              >
                How it works
              </Link>
            </div>
          </div>
        </Reveal>
      </section>
    </div>
  );
}
