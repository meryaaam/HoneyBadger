# Responsible use and data handling

HoneyBadger watches attackers. That carries obligations, both technical and ethical.

## What the honeypot never does

- **It never executes attacker input.** The SSH shell is simulated (`backend/fakeshell.py`): commands get prepared answers; nothing runs on the host.
- **It never downloads payloads.** `wget` and `curl` produce fake output; only the URL is recorded. With `HB_CAPTURE_PAYLOADS=true`, metadata is staged in a no-exec quarantine folder for manual review; files are still never executed.
- **It never connects to attacker-supplied addresses.** The only outbound traffic is the cached GeoIP lookup (`ip-api.com` by default). `HB_GEOIP_PROVIDER=maxmind` with a local database removes it; `maxmind` without a database path disables lookups altogether.
- **It never stores passwords in clear.** SSH and form passwords are stored as `sha256:` hashes; password-like URL parameters are replaced by `REDACTED`. Verified in `docs/TEST_REPORT.md`.
- **It never attacks back.** Observation only.

## Deployment rules

- Expose only the honeypot ports (8022, 8081). Keep PostgreSQL, the API, the dashboard, Prometheus and Grafana on a private network or behind a VPN.
- Change the Grafana admin password (`HB_GRAFANA_ADMIN_PASSWORD`) and disable anonymous access (`HB_GRAFANA_ANONYMOUS=false`) before exposing anything.
- Run it on a machine that holds nothing valuable, and keep it updated.

## Personal data

Source IP addresses can identify people, so they are personal data under laws such as the GDPR. Keep them only as long as needed (the default retention is 6 months, `backend/retention.py`), restrict access to the database, and do not publish raw IP lists.

## Reporting what you find

- If an attacking address belongs to a compromised machine or network, report it to that network's abuse contact (found in WHOIS), not to the person.
- Report malware URLs to the hosting provider or to a public malware-sharing service, without downloading the files yourself.
- If you find a vulnerability in HoneyBadger itself, tell the maintainers privately first and give them time to fix it before discussing it publicly.

## Datasets

The Kaggle dataset used by the notebooks lists its license as *Unknown*: it is downloaded on demand and is not committed to this repository.
