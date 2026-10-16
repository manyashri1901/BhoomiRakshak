// frontend/src/lib/x509Setup.ts
//
// @peculiar/x509 needs a Reflect polyfill and an explicit WebCrypto
// provider registration before any other call into the library — in the
// browser, the provider is just the browser's own native
// `window.crypto`, no extra dependency needed (unlike Node, which needs
// `node:crypto`'s `webcrypto` export wired in the same way — see
// lib/x509Keys.ts on the backend). Imported once, for its side effect
// only, at the top of certificateVerify.ts.

import "reflect-metadata";
import * as x509 from "@peculiar/x509";

x509.cryptoProvider.set(crypto as unknown as Crypto);
