# Exam security validation — 2026-09-21

Base: `51bc5c0` from `origin/main`. Work was performed in an isolated checkout. The user's running OJ, host MariaDB, deployment secrets and host Nginx configuration were not modified.

## Automated checks

- **35 pytest cases passed**, including the prior signature, source-IP and device-name checks. New cases use real isolated MariaDB for session bindings, missing device identity, account-wide revocation, copied-identity context changes, source-IP account policy, concurrent account claims, registration policy, expired/revoked/legacy sessions, authenticated problem access, provenance, denied/incomplete submission auditing and conflicts during judging.
- **18 HTTPS integration checks passed**, using actual Nginx, Uvicorn, MariaDB and Docker judge containers. The client validates the generated certificate and hostname. Covers HTTP redirect, HTTP backend refusal, HSTS, Secure/HttpOnly cookies, closed registration, anonymous problem refusal, login, repeat-login event recording, restoration, C AC, C++ AC, WA, CE, saved history, throttling, submission provenance, rejected conflicting login, revocation of the earlier session and denied-submission audit.
- Device-name integration check passed: each login keeps its observed name; a matching name cannot override changed source context.
- A separate temporary database was initialized with the actual pre-change `database.py` from `51bc5c0`, then upgraded and initialized twice. Password authentication, prior login events and source code were preserved; old submission provenance remained NULL, unbound legacy tokens were rejected and active old alerts became account blocks.
- Frontend production build passed with the existing local dependencies (`npm --prefix front run build -- --configLoader native`). The native config loader avoids writing Vite temporary files into the original checkout's dependency directory.
- Nginx integration configuration validation and `git diff --check` passed.

Pytest reported two dependency deprecation warnings from Starlette/httpx/AnyIO; no test failures.

## Browser workflow

The Codex in-app browser exercised the built frontend with a disposable account in the isolated environment:

1. Anonymous view has no problem descriptions and no registration button in exam mode.
2. Wrong password is rejected; correct login loads both problem choices and their descriptions/samples.
3. Selecting problem 1002 and submitting C returns AC and adds a history row.
4. Reload restores the user, problems and saved history with the same request fingerprint.
5. Switching to C++, editing the Monaco editor and submitting returns AC with a second history row.
6. A fixture source conflict denies new access; the earlier browser's next submit is rejected with the proctor message.
7. Reload after revocation shows no user, problems or history and disables submission. The final frontend preserves the server's proctor message instead of suggesting repeated login.

The browser did not trust the temporary self-signed test certificate. Browser UI checks therefore used an explicit loopback-only HTTP development override with test-only credentials; no security interstitial was bypassed and no system trust settings were changed. The separate API integration suite validated HTTPS with certificate verification enabled. Production browser certificate provisioning and a second physical Windows computer were not exercised in this run.

## Deployment and remaining boundary

Follow [exam-security.md](exam-security.md) before deployment. Install a certificate trusted by all exam clients, configure the exact proxy peer and verify that Nginx sees distinct exam-machine IPs. Existing unbound sessions require new login after upgrade. Same-IP account restriction is enabled by default in exam mode and can block legitimate users behind shared NAT.

These changes bind and check observed request context. They do not establish physical-machine identity: identical copied cookies and fingerprints behind the same observed IP remain indistinguishable without an additional device credential/managed-client design. No WebAuthn or device-certificate enrollment was added. The PR updates code and deployment configuration; it does not install TLS on the current production host.
