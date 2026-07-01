# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed
- **All hooks were reporting success without confirming the device actually served the new cert**, so three devices silently served stale/expired certificates while certbot's local certs were current. All six hooks now verify the served leaf certificate on `:443` after deploy and fail loudly on mismatch (`--no-verify` to skip). Verification is bounded by an absolute wall-clock deadline (`VERIFY_DEADLINE`, checked each iteration via a monotonic clock) so a deploy hook can never hang certbot: 120s for the fast devices, 180s for uisp, 300s for nas0ipmi (covers its ~90s BMC reboot).
- laserjet: never actually installed a cert — `curl -X POST … -L` re-POSTed the printer's `303` redirect and got a `405`, and the upload used wrong form fields. Now follows the redirect as a GET with a cookie jar, uses the real EWS fields (`FileName`/`Password`/`Finish`), and treats HTTP ≥ 400 as failure (`--fail-with-body`).
- nas0ipmi: renewals uploaded and validated but never took effect. The warm CGI reset (`op=main_bmcreset`) stores a replaced cert but does not re-load it; the hook now does a **cold reset** via `ipmitool … mc reset cold` (requires ipmitool + IPMI-over-LAN). Also stops tagging the private key with a certificate MIME type and converts the key to PKCS#1 before upload.
- ucg: a UniFi OS firmware update repointed the served certificate to a new UUID (`local-certs.conf` / `settings.yaml activeCertId`), orphaning the symlink the hook relied on. The hook now reads the active cert/key paths from `local-certs.conf` at deploy time, overwrites those files, and reloads nginx.

### Security
- nas0ipmi: BMC login credentials are now sent via a temp file (`curl -d @file`) instead of appearing on the curl command line, where they were visible in `ps` while the request ran.
- laserjet: the PKCS12 password is now read from a temp file (`curl -F 'CertPwd=<file'`) instead of appearing on the curl command line.
- cyberpower: session token values (`token`, `temp_token`) are redacted from logged response bodies.

### Changed
- cyberpower: a login-verify response without a `token` field now raises a descriptive RuntimeError instead of a bare KeyError.
- README and CLAUDE.md script lists updated for the cyberpower and nas0ipmi hooks; CLAUDE.md structure now covers `tests/` and `pyproject.toml`.

## [2026-03-21]

### Added
- Ruff linting (22 rule categories), mypy strict type checking, and pytest CI jobs.
- 52 unit tests covering all deploy hooks and install.py.
- Secrets scanning CI job to catch accidental key commits (`.py`, `.sh`, `.conf`, `.md`, `.json`, `.yml`, `.yaml`).
- `install.py` for copying hooks to certbot's renewal-hooks directory.
- Troubleshooting section in README.
- CONTRIBUTING.md with development and contribution guidelines.
- CHANGELOG.md.
- README badges for CI, Python version, license, ruff, and mypy.
- `autouse` env isolation fixture in tests to prevent env var leakage.
- `id_ed25519*` and `id_ecdsa*` to `.gitignore`.

### Changed
- Minimum Python version raised from 3.10 to 3.13.
- Replaced cryptic fallback error messages with descriptive context.
- Simplified `install.py` to use pathlib consistently; no longer calls `sys.exit(0)` on success.
- Simplified temp file management to use `tempfile.TemporaryDirectory`.
- Increased UISP reload timeout to 600 seconds.
- Updated CI actions to v5/v6 for Node.js 24 compatibility.
- `test.py` now forwards extra arguments to the deploy hook.

### Fixed
- `mkstemp` mode argument.

## [2026-01-29]

### Added
- UISP deploy hook (`uisp.mousebrains.com.py`).
- UISP setup documentation (`README.uisp.md`).

### Changed
- Simplified LaserJet MFP authentication to OAuth2 password grant.

## [2026-01-28]

### Added
- HP Color LaserJet M452dn deploy hook (`laserjet.mousebrains.com.py`).
- LaserJet M452dn setup documentation (`README.laserjet.md`).

## [2026-01-27]

### Added
- HP LaserJet MFP deploy hook (`ljscan.mousebrains.com.py`) with CDM OAuth2 authentication.
- LaserJet MFP setup documentation (`README.ljscan.md`).

### Changed
- Rewrote OAuth2 flow multiple times to match HP printer firmware expectations.

## [2026-01-26]

### Added
- UniFi Cloud Gateway deploy hook (`ucg.mousebrains.com.py`).
- UCG setup documentation (`README.ucg.md`).
- GitHub Actions CI for syntax checking and secrets scanning.
- CLAUDE.md project guidelines.

### Changed
- Refactored UCG hook into `main()` with argparse, logging, and `--logfile` support.
- Removed legacy bash deployment scripts.
