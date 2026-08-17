// A wax-seal motif for signature/certificate validity — fitting for a
// PKI land-records system, where a cryptographic signature plays the same
// role a wax seal historically played: proof a document is genuine and
// unaltered. Valid = an intact seal, stamped in Camel. Invalid = the same
// seal in Wax Seal Red, visibly cracked.

const BLOB_PATH =
  "M22.69,12.00 C22.80,13.88 21.38,16.35 20.10,17.89 C18.82,19.43 16.86,20.68 15.00,21.24 " +
  "C13.15,21.80 10.95,21.74 8.99,21.27 C7.03,20.79 4.27,19.93 3.22,18.38 C2.17,16.84 2.57,14.04 2.69,12.00 " +
  "C2.80,9.96 2.90,7.76 3.92,6.13 C4.95,4.50 6.95,2.87 8.82,2.22 C10.70,1.57 13.41,1.51 15.17,2.24 " +
  "C16.93,2.98 18.14,5.00 19.40,6.63 C20.65,8.25 22.57,10.12 22.69,12.00 Z";

interface WaxSealProps {
  valid: boolean;
  className?: string;
}

export function WaxSeal({ valid, className }: WaxSealProps) {
  const fill = valid ? "var(--color-camel)" : "var(--color-wax-seal)";
  const emboss = valid ? "var(--color-coffee)" : "#3d1a1a";

  return (
    <svg viewBox="0 0 24 24" className={className ?? "h-5 w-5"} aria-hidden="true">
      <path d={BLOB_PATH} fill={fill} />
      {/* pressed emboss ring, suggesting a stamped impression */}
      <circle cx="12" cy="12" r="6.5" fill="none" stroke={emboss} strokeWidth="0.6" opacity="0.45" />
      {valid ? (
        <path
          d="M8.7 12.3l2.2 2.2 4.4-4.6"
          fill="none"
          stroke="var(--color-apricot)"
          strokeWidth="1.6"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      ) : (
        <path
          d="M10.2 7.5l1.4 3.1-2.1 1.4 2.6 2.4-1.2 3.4"
          fill="none"
          stroke="var(--color-apricot)"
          strokeWidth="1.4"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
    </svg>
  );
}
