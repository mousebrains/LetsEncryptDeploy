# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed
- Minimum Python version raised from 3.10 to 3.13.
- Replaced cryptic fallback error messages with descriptive context.

### Added
- Troubleshooting section in README.
- CONTRIBUTING.md with development and contribution guidelines.
- This changelog.
- README badges for CI, Python version, license, ruff, and mypy.

## [2026-03-21]

### Added
- Ruff linting (22 rule categories), mypy strict type checking, and pytest CI jobs.
- 48 unit tests covering all deploy hooks and install.py.
- Secrets scanning CI job to catch accidental key commits.
- `install.py` for copying hooks to certbot's renewal-hooks directory.

### Changed
- Simplified temp file management to use `tempfile.TemporaryDirectory`.
- Increased UISP reload timeout to 600 seconds.
- Updated CI actions to v5/v6 for Node.js 24 compatibility.

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
