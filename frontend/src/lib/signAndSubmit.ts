// lib/signAndSubmit.ts
//
// The shared prepare -> sign -> submit sequence every signing action
// (transaction creation, VO approval, registrar approval) follows:
//   1. prepare() asks the server to validate everything and freeze the
//      exact bytes that must be signed, returning {nonce, payload}.
//   2. The private key is unwrapped from its encrypted blob using the
//      password the user just entered — this throws WrongPasswordError on
//      a wrong password, before anything is signed.
//   3. The browser signs EXACTLY `payload`'s bytes — no re-derivation.
//   4. submit() sends back only {nonce, signatureValue}; the server does
//      the rest (never trusting payload from the client).
// The unwrapped CryptoKey is never returned or retained — it only exists
// for the lifetime of this function call.

import { unwrapPrivateKey, signCanonicalString, type WrappedKeyBlob } from "./clientCrypto";
import type { PreparedSignature } from "../api/transactions";

export async function signAndSubmit<T>(
  wrappedKey: WrappedKeyBlob,
  password: string,
  prepare: () => Promise<PreparedSignature>,
  submit: (nonce: string, signatureValue: string) => Promise<T>,
): Promise<T> {
  const prepared = await prepare();
  const privateKey = await unwrapPrivateKey(wrappedKey, password);
  const signatureValue = await signCanonicalString(privateKey, prepared.payload);
  return submit(prepared.nonce, signatureValue);
}
