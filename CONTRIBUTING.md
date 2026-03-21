# Contributing

Contributions are welcome. This document covers the development workflow and conventions.

## Prerequisites

- Python 3.13+
- [ruff](https://docs.astral.sh/ruff/) for linting
- [mypy](https://mypy.readthedocs.io/) for type checking
- [pytest](https://docs.pytest.org/) for testing

Install the development tools:

```bash
pip install ruff mypy pytest
```

## Running checks

All three must pass before submitting a pull request:

```bash
ruff check .
mypy --strict *.py
pytest -v
```

These same checks run in CI on every push and pull request.

## Deploy hook conventions

Each deploy hook is a standalone Python script named `<fqdn>.py`. The scripts must remain self-contained with no local imports -- certbot copies individual files into `/etc/letsencrypt/renewal-hooks/deploy/`, so shared modules are not available at runtime.

When writing or modifying a deploy hook:

- **Filename**: Use the device's FQDN as the script name (e.g., `printer.example.com.py`).
- **Hostname derivation**: The hostname is derived from the filename by stripping `.py`. Do not hardcode hostnames.
- **Argument parsing**: Use `argparse` with `--logfile`, `--verbose`, and device-specific options.
- **Logging**: Log to `/var/log/<fqdn>.log` by default. Support `--logfile ""` for stderr.
- **Environment variables**: Read `RENEWED_DOMAINS` and `RENEWED_LINEAGE` from the environment. Exit silently (`sys.exit(0)`) if the hostname is not in `RENEWED_DOMAINS`.
- **Subprocess calls**: Always include a `timeout` parameter (180s default, longer for slow operations). Capture output and truncate with `.decode(errors="replace")[:500]`. Check return codes.
- **Error handling**: Catch `subprocess.TimeoutExpired`, `KeyError`, `FileNotFoundError`, and `RuntimeError` explicitly. Use a generic `except Exception` fallback with `logging.exception()`. Call `sys.exit(1)` on any failure.
- **Security**: Never pass credentials on the command line. Use environment variables for openssl (`-passout env:VAR`) and temporary netrc files for curl (`--netrc-file`). Clean up temp files with context managers.
- **Type hints**: Annotate all functions. The project uses mypy strict mode.

## Adding a new deploy hook

1. Copy an existing hook that's closest to your target device.
2. Rename to `<your-fqdn>.py`.
3. Modify the deployment logic (SCP, curl, etc.) for your device.
4. Add a setup document as `README.<short-name>.md`.
5. Add tests in `tests/test_<short-name>.py`.
6. Update `README.md` — add the hook to both the **Scripts** and **Device-specific setup** sections.

## Tests

Tests live in `tests/` and use pytest. Each deploy hook has a corresponding test file. Tests mock `subprocess.run` and filesystem operations -- they do not require actual devices.

To run a single test file:

```bash
pytest tests/test_ucg.py -v
```

## Code style

- Line length: 100 characters.
- Ruff enforces style, imports, security, and bug-prevention rules. See `pyproject.toml` for the full rule set.
- Do not add `# type: ignore` comments without a specific mypy error code.

## Pull requests

- Keep changes focused. One feature or fix per PR.
- Ensure all CI checks pass.
- Update the changelog in `CHANGELOG.md` under `[Unreleased]`.
- Add or update tests for any changed behavior.

## License

By contributing, you agree that your contributions will be licensed under the GPLv3.
