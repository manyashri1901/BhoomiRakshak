# Attack Simulation Results

Run: 2026-10-16T18:55:05.422Z

**12 of 12 attacks blocked**

| # | Attack | Expected defence | Actual response | Result |
|---|---|---|---|---|
| 0 | Tampered document (hash mismatch) | documentIntegrity.match = false | documentIntegrity.match = false | PASS (blocked) |
| 1 | Forged signature (unregistered key) | submit rejected (409/400) | HTTP 409: Signature does not match the prepared payload. | PASS (blocked) |
| 2 | Signature from the wrong key (another real user's key) | submit rejected (409/400) | HTTP 409: Signature does not match the prepared payload. | PASS (blocked) |
| 3 | Revoked certificate used to sign | prepare rejected 403 before any signing | HTTP 403: Cannot sign: Certificate was revoked: Attack simulation | PASS (blocked) |
| 4 | Expired certificate used to sign | prepare rejected 403 before any signing | HTTP 403: Cannot sign: Certificate expired on 2025-10-16T18:54:10.000Z. | PASS (blocked) |
| 5 | Replayed (already-used) nonce | first submit 201, replay rejected 409 | first HTTP 201, replay HTTP 409: This nonce has already been used — call prepar… | PASS (blocked) |
| 6 | Wrong-role approval (Landowner acting as Village Officer) | rejected 403 (role check) | HTTP 403: Forbidden: insufficient role | PASS (blocked) |
| 7 | Skipped stage (Registrar before Village Officer) | rejected 400 (not pending Registrar review) | HTTP 400: Transaction is not pending Registrar review | PASS (blocked) |
| 8 | Double sale (race: 2 simultaneous prepare+submit on same record) | exactly one submit 201, the other 409 | submitA HTTP 409, submitB HTTP 201 | PASS (blocked) |
| 9 | Tampered audit log row (then restored) | row's own hash matches before tamper, mismatches after tamper, matches again after restore | before=true, after tamper=mismatch (detected), after restore=true [whole-chain … | PASS (blocked) |
| 10 | Upload of a fake PDF (EXE magic bytes, .pdf filename) | rejected 415 before touching disk | HTTP 415: Unsupported file type. Only PDF, PNG, and JPEG documents are accepted. | PASS (blocked) |
| 11 | Non-admin calling certificate revoke | rejected 403 (role check) | HTTP 403: Forbidden: insufficient role | PASS (blocked) |
