# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — Pending release

Initial Phase 1 alpha. See [release notes](RELEASE_NOTES.md) for installation and known limitations.

### Added

- Local secret and PII detection with a deterministic sanitization pipeline.
- Configurable privacy policies and task-aware rules for locations and URLs.
- `ALLOW`, `DROP`, `TOKENIZE`, `ABSTRACT`, and `LOCAL_ONLY` actions.
- The `sanitize()` Python API, redacted diagnostics, and `SafeExternalPayload`.
- Input validation, evaluation fixtures, and adversarial regression tests.

### Evaluation

- Supplied report: 114/114 cases passed; no recorded secret, PII, or diagnostic leaks.
- Required information retained in 38/38 applicable cases, with no incorrect removals.
- Average processing time: 19.61 ms; P95: 12.45 ms, including the first case in the run.
- These benchmark results do not establish the result of the full test suite or guarantee detection of every input.
