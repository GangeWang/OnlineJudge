# Login device-name validation

Validated on the local Docker/MariaDB deployment on 2026-09-20.

- 17 tests passed: 10 existing security checks plus 7 name-resolution/configuration checks.
- Real database checks passed: additive migration, repeated initialization, preservation of all existing login-event fields, empty unknown name, safe enrichment of unnamed same-IP/same-device events, preservation of already-recorded names, and new-event name insertion.
- All 19 pre-existing login records remained present after migration and fixture cleanup.
- A separate physical Windows computer registered and logged in twice through the existing Nginx API. Registration and both logins returned HTTP 200. The database contained one event with `ip_address=192.168.137.1` and `device_name=ganges-desktop`.
- Client-supplied fake `X-Device-Name`, `device_name` form field and `X-Real-IP` values did not replace the server-selected name or source IP.
- The physical-client result used an explicit administrator IP/name mapping. Reverse DNS on this LAN did not provide a hostname; it must not be represented as automatic OS-hostname discovery. Successful PTR lookup and timeout behavior were tested with controlled resolver responses and a 0.5-second lookup budget.
- Test users and dependent records were removed. No test files were written to Windows; temporary SSH and local build/test files were cleaned up. Deployment `.env` remains local and untracked.

Database test script (explicitly creates and removes its own fixture user): `backend/tests/integration_device_names.py`, requiring `OJ_INTEGRATION_TEST=1`. It also runs the application's normal schema initialization; use a disposable database first when validating future migration changes.
