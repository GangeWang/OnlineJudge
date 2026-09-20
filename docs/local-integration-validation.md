# Local integration validation — 2026-09-20

Tested the changes from PR #11 (`codex/pr`, starting at `1f20e01`) on macOS arm64. The local main checkout was `46b53ec`. The previously reported short SHA `87470c6` was not present; the matching published fix is `1f20e01`.

## Findings fixed

- A non-ASCII HMAC signature in `oj_device` caused HTTP 500. Reject malformed signatures before constant-time comparison and rotate the cookie.
- Uvicorn rewrote the socket peer from `X-Forwarded-For` before application proxy validation. A live request recorded injected `198.51.100.88` instead of the explicitly trusted proxy's `X-Real-IP`. Disable Uvicorn proxy header processing in Docker and documented local startup commands.
- Browser reload lost the frontend login state, history and device warning despite a valid backend session. Restore these from a non-cacheable `/session` endpoint and filter alerts for the current session's device.

## Results

- **9 security unit tests passed** (`python -m pytest tests -q` in backend container).
- **25 integration checks passed, 0 failed**, using real HTTP, Nginx, MariaDB and Docker sandbox execution. No database or judge mocks.
- Backend Dockerfile built successfully; Compose configuration expanded successfully. Docker 29.8.0, Compose 5.5.1; rebuilt backend Python 3.14 with Uvicorn 0.53.0. MariaDB 11 and Nginx Alpine test images; existing `onlineoj-sandbox:latest` used for judging.
- Frontend production build passed using the locally installed dependencies.
- Legacy schema migration from `46b53ec` passed with preserved password authentication, session rows and login-event rows; repeated initialization passed.
- `git diff --check` passed.

HTTP checks cover signed-cookie issuance, unsigned/tampered/non-ASCII-cookie replacement, missing/short secret startup rejection, Secure/HttpOnly/SameSite cookie attributes, forwarding-header injection, login reuse, device/account restrictions, alert expiration, session restoration, alert isolation, submission rate limiting, actual C compilation and AC result, and database persistence.

## Browser workflow

The workflow was exercised at **http://127.0.0.1:80** using the Codex in-app browser. Safari control repeatedly timed out before any interaction, so **Safari-specific compatibility is not verified**.

Passed: anonymous submission rejection; registration; correct and incorrect passwords; selecting problems; editing code; C and C++ AC; WA; CE with compiler output; persisted answer history; session/history restoration after reload; repeat login without false warning; refusal to log into a second account on the same device; cross-device warning; blocked submission before and after reload; warning persistence after reload.

Cross-device browser testing used a controlled first-device login in the temporary database after expiring only the dedicated fixture account's prior login events. This was a logical-device scenario, not a second physical computer.

The original host Nginx temporarily routed only Host `127.0.0.1` to the isolated frontend/API. Its original configuration was restored after browser verification. Original backend containers and the host database were not replaced or modified. Test database dumps, credentials, logs, generated frontend assets and the temporary worktree are disposable and are not part of this commit.

## Reproduce the HTTP suite

From the repository root, with Docker, Compose and `onlineoj-sandbox:latest` available:

```sh
export DEVICE_SECRET="$(openssl rand -hex 32)"
docker compose -p onlineoj-integration -f docker-compose.yml -f deploy/integration/compose.yml up -d --build backend nginx
docker compose -p onlineoj-integration -f docker-compose.yml -f deploy/integration/compose.yml exec -T -e OJ_INTEGRATION_TEST=1 backend python tests/integration_workflow.py
docker compose -p onlineoj-integration -f docker-compose.yml -f deploy/integration/compose.yml down --volumes
unset DEVICE_SECRET
```

The override uses loopback ports 18000/18080, a separate Compose network, a tmpfs database, explicit proxy trust and test-only database credentials. Ensure subnet `172.29.247.0/24` is available. All test API requests run inside the backend container. The script refuses execution unless `OJ_INTEGRATION_TEST=1` and the database host is `db`.

## Scope and deployment notes

HTTPS cookie attributes were inspected on actual responses; a real TLS handshake and browser HTTPS deployment were not tested. The workflow used the explicit HTTP cookie mode. Docker Desktop forwarding can expose a gateway IP, so production proxy trust must be configured for the actual topology.

Old unsigned or truncated legacy signatures are intentionally not trusted or migrated: the old default signing key was public. Such cookies receive a fresh identity; upgrading during an active three-hour login window can therefore trigger an alert if IP/fingerprint also changes. Plan rollout outside active sessions. Cookie/fingerprint identity remains a risk signal, not proof of physical device identity.

## LAN proxy trust follow-up

The host deployment was checked after merging PR #11. Its Nginx-to-backend socket peer was observed as `172.18.0.1`, while the backend trusted only loopback; consequently the forwarded LAN client IP was discarded. The deployment now sets `TRUSTED_PROXY_CIDRS=172.18.0.1/32,127.0.0.1/32,::1/128` in its ignored `.env`, preserving the existing signing key. The backend container was recreated and its effective environment verified. This address is specific to the observed host topology, not a universal Docker default.

A temporary HTTP probe invoked the real `main.client_ip` implementation without database access. Using the host LAN interface through a separate host Nginx and Docker published port produced:

- LAN source preserved: client `192.168.137.6`, socket peer `172.18.0.1`.
- Injected `X-Real-IP` and `X-Forwarded-For` were overwritten by Nginx; client remained `192.168.137.6`.
- An untrusted sibling container's forged headers were ignored; client equaled its socket peer (`172.18.0.5`).

This verifies the actual host LAN interface and proxy path, but does not substitute for a request from a separate physical LAN computer. The original website remained accessible through its LAN IP. The probe containers/processes/files were removed after verification; `.env` remains as required deployment configuration and is never committed.

The expanded security regression suite passed: **10 tests passed**. Compose validation and `git diff --check` also passed.

## Separate physical Windows client verification

The remaining physical-client check was completed using a second Windows 11 computer over SSH. Windows routing selected source `192.168.137.1` on `Wi-Fi 2` for destination `192.168.137.6`; its other Ethernet interface had `192.168.10.83`, which was not the source of this connection.

Two uniquely named, disposable accounts were registered and logged in through the existing host Nginx at `http://192.168.137.6/api`. Both registration and login returned HTTP 200, and `/session` returned the expected user. The second case supplied forged `X-Real-IP: 203.0.113.99` and `X-Forwarded-For: 198.51.100.77`.

Direct verification of the real backend database showed `login_events.ip_address = 192.168.137.1` for both cases. This matches the remote computer's selected interface and confirms that the forwarded IP cannot be overridden with those client-supplied headers.

The two test accounts and their dependent session/login records were removed immediately after verification. No test files were written on the Windows computer. SSH connection state, temporary host-key file, encoded test commands and local output logs were removed. SSH credentials were not saved to the repository or report.
