# Changelog

All notable user-facing changes in `seekr` are recorded here.
Format follows Keep a Changelog; versions follow SemVer.

## [0.1.0] - 2026-09-08

### Added
- `diagnose <URL>`: cross-vantage diagnosis with confidence, backing
  evidence, interpretation, and next step.
- `compare <URL>`: per-vantage differences without diagnosis.
- `probe <URL>`: raw per-vantage evidence collection.
- `trace <URL>`: per-stage connectivity view
  (DNS/TCP/TLS/HTTP/identity/content).
- `batch <FILE>`: bounded parallel runs over a target list with
  input-order results and aggregate exit code.
- `completions <shell>`: shell completions (bash, zsh, fish,
  powershell, elvish).
- Vantages: direct, HTTP/HTTPS/SOCKS5 proxies, proxy files.
- Identity: egress IP/country/ASN auto lookup per vantage (on by
  default, `--no-identity-lookup` to disable, `--geo-map` to override).
- Adaptive confirmation within a per-target probe budget
  (`--max-probes`, default 10).
- JSON output (`--json`, `schema_version: "1"`, stdout only) and quiet
  mode (`--quiet`).
- Exit codes: 0 healthy, 1 restriction, 2 bad args, 3 unreachable,
  4 vantage failure, 5 timeout, 6 internal, 7 partial/unknown.
- Credential redaction across output, logs, errors, and debug views.
