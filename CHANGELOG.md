# Changelog

## Unreleased (branch `presentation-prep`)

Base: `93a9d69` (`main` after PR #2). Every bug fix comes with a test; see `docs/TEST_REPORT.md` for before/after results.

### Fixed

- **Pipeline crash on payload events.** `backend/pipeline.py` used `record_payload_captured` without importing it; every `wget`/`curl` event logged a pipeline error and skipped its metrics.
- **HTTP 500 on `POST /phpmyadmin`.** The route passed the request to a handler that takes no argument (`backend/http_routes.py`).
- **Exploit payloads lost.** The HTTP sensor stored only the path, so `/?id=1' OR 1=1--` was saved as `/` and never classified as T1190. It now stores the URL-decoded query string, redacts password-like parameters (`pwd=REDACTED`) and caps the length at 2,048 characters (`backend/httpd.py`).
- **HTTP logins tagged as scans.** A POST with credentials to `/admin` or `/wp-login.php` was T1595; the credential rule now runs before the scanner rule (`backend/mitre.py`).
- **Handshake rows in the live feed.** `/events` and the WebSocket served SSH handshake rows (no attacker action) since the move to PostgreSQL; they are still stored but filtered (`backend/storage.py`, `backend/api.py`).
- **Empty activity chart on the dashboard.** `/stats/timeseries` returned a bare list; it now returns `{window, bucket_seconds, points}` as `dashboard/src/types.ts` expects, and `/stats` returns `window` as `"1h"` instead of `"1:00:00"`.
- **Test suite did not run.** `pytest` stopped with 3 collection errors. `test_api.py` was rewritten for the PostgreSQL-backed API, the default run is limited to `backend/tests`, and the live scenario file skips cleanly without its plugin or a running stack.
- **Live scenario tooling.** Import paths fixed (`tests/attack_scenarios.py`, `tests/test_attack_scenarios.py`); `psycopg2-binary` added to `backend/requirements-dev.txt`; `PYTHONPATH` fixed in `tests/Dockerfile.test`; handshake and command rows no longer counted as login events.

### Added

- **Attack simulator** (`backend/sim/simulate.py`): `python -m sim.simulate --count N --delay S` sends harmless SSH and HTTP attacks and prints the recorded techniques. Previously a stub.
- **Tests:** `backend/tests/test_mitre.py` and `test_pipeline.py` (previously empty files), `test_httpd.py` (new), `test_api.py` (rewritten; runs against a real PostgreSQL when `HB_TEST_DATABASE_URL` is set).
- **Pair 2 notebook** `pair2_anomaly_detection.ipynb` (objective 2, Siwar and Shayma). Confirmed by Shayma on 2026-11-22.
- **Reproducibility:** both notebooks save their settings and results to `results/pair1_results.json` and `results/pair2_results.json`; `scripts/run_analysis.py` re-runs them and checks 50 values against `scripts/expected_results.json`; `requirements-analysis.txt`.
- **Documentation:** `docs/TEST_REPORT.md`, `docs/RESULTS_AND_ANALYSIS.md`, `docs/DEMO_GUIDE.md`, `docs/PROJECT_EXPLAINED_FROM_ZERO.md`, `docs/PROFESSOR_QA.md` (French), `docs/PRESENTATION_SCRIPT.md` (French), `docs/FINAL_PROJECT_REPORT.md` (French), `docs/RESPONSIBLE_DISCLOSURE.md` and `docs/ANALYSIS.md` (previously empty), `docs/img/dashboard_live.png`.
- French presentation deck (15 slides with speaker notes), hosted outside the repository; linked from `docs/PRESENTATION_SCRIPT.md`.

### Changed

- **README:** corrected the PostgreSQL host port (15432), the clone folder name, the simulator and testing claims, and removed links to the missing `docs/API.md` and `docs/ROADMAP.md`; added the "Offline machine-learning analysis" section.
- **PROJECT_INDEX.md:** updated for the new files and the fixed issues.
- **.gitignore:** `pair2_predictions.csv`.

### Known open issues

- Brute force (T1110) vs credential stuffing (T1110.004) is defined differently in the README, the code and the tests: team decision needed.
- T1078 is never produced.
- `tests/integration/` and `tests/security/` contain empty placeholder files.
- `/stats` totals include SSH handshake rows.
