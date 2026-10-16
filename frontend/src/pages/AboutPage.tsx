import { AlertTriangle, Fingerprint, Link2, ShieldCheck, UserCheck } from "lucide-react";
import { Reveal } from "../components/ui/Reveal";
import { Card } from "../components/Card";
import { H1, H2, SECTION_LABEL, CONTAINER, SECTION_PADDING } from "../components/ui/typography";

const APPROACH = [
  {
    icon: UserCheck,
    title: "Digital identities",
    description:
      "Every participant holds a verified digital identity issued through a certificate authority hierarchy, not just a database row.",
  },
  {
    icon: Fingerprint,
    title: "Signed transactions",
    description: "Every registration, transfer, and update is signed by the person who took the action.",
  },
  {
    icon: ShieldCheck,
    title: "Tamper-evident records",
    description: "Any after-the-fact change to a record or its history is independently detectable.",
  },
  {
    icon: Link2,
    title: "Role-based approval chain",
    description: "A land record moves through Landowner, Village Officer, and Registrar in strict order.",
  },
];

const SCOPE_LIMITS = [
  "The certificate authority is operated by this project and is not a licensed Certifying Authority.",
  "No integration with government land record databases.",
  "No trusted timestamping.",
  "Intended to complement, not replace, existing registration systems.",
];

export function AboutPage() {
  return (
    <div className="flex flex-col">
      <section className="pt-8 pb-14 sm:pb-18 lg:pb-24">
        <Reveal className={CONTAINER}>
          <span className={SECTION_LABEL}>About</span>
          <h1 className={H1}>What this project is</h1>
          <p className="mt-5 max-w-2xl text-base text-slate-600">
            BhoomiRakshak is a PKI-based land record and ownership security project. It shows how
            verified digital identities, signed transactions and tamper-evident records can add
            trust to land registration workflows.
          </p>
        </Reveal>
      </section>

      <section className={`${SECTION_PADDING} bg-slate-50`}>
        <Reveal className={CONTAINER}>
          <span className={SECTION_LABEL}>The problem</span>
          <h2 className={H2}>Digitised records still leave gaps</h2>
          <p className="mt-4 max-w-2xl text-base text-slate-600">
            Paper-based and loosely digitised land records can be altered after the fact without
            leaving a reliable trace, making forged documents hard to catch. The same property can
            still be sold to more than one buyer when different offices process transactions
            without cross-checking each other. And confirming who actually authorised a change
            often still depends on manual verification across multiple offices rather than on
            verifiable proof.
          </p>
        </Reveal>
      </section>

      <section className={SECTION_PADDING}>
        <Reveal className={CONTAINER}>
          <span className={SECTION_LABEL}>The approach</span>
          <h2 className={H2}>Identity, signatures, and a verifiable chain</h2>
          <p className="mt-4 max-w-2xl text-base text-slate-600">
            Every action that changes a land record is tied to a real, verified identity and
            carried out through a strict, role-based approval chain.
          </p>
          <div className="mt-10 grid grid-cols-1 gap-5 sm:grid-cols-2">
            {APPROACH.map(({ icon: Icon, title, description }, i) => (
              <Reveal key={title} delay={i * 80}>
                <Card className="flex h-full items-start gap-4">
                  <Icon className="mt-0.5 h-5 w-5 shrink-0 text-teal" aria-hidden="true" />
                  <div>
                    <h3 className="text-base font-semibold text-slate-900">{title}</h3>
                    <p className="mt-1 text-sm text-slate-600">{description}</p>
                  </div>
                </Card>
              </Reveal>
            ))}
          </div>
        </Reveal>
      </section>

      <section className={`${SECTION_PADDING} bg-slate-50`}>
        <Reveal className={CONTAINER}>
          <span className={SECTION_LABEL}>Scope and limits</span>
          <h2 className={H2}>Honest about what this is, and isn't</h2>
          <Card className="mt-8">
            <ul className="flex flex-col divide-y divide-slate-100">
              {SCOPE_LIMITS.map((item) => (
                <li key={item} className="flex items-start gap-3 py-3 first:pt-0 last:pb-0">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" aria-hidden="true" />
                  <span className="text-sm text-slate-700">{item}</span>
                </li>
              ))}
            </ul>
          </Card>
        </Reveal>
      </section>
    </div>
  );
}
