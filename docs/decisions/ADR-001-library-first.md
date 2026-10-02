# ADR-001: Library-first, no HTTP yet

## Status
Accepted

## Date
2026-10-02

## Context
Occulens is designed as a local-first privacy layer for AI agents. In Phase 1, our core mandate is establishing reliable context sanitization:
`task + context -> detect -> decide -> transform -> sanitized context`.

We evaluated whether to expose an HTTP API (e.g., via FastAPI) immediately or package Occulens purely as an in-process library.

Key requirements:
- Zero networking/framework overhead for core sanitization logic.
- Frictionless unit and integration testing without running mock servers.
- Direct composability inside existing agent workflows.
- Isolation of core privacy algorithms from transport concerns.

## Decision
Build Occulens as a Python library first, with the primary public interface:
```python
sanitize(task: str, context: str, policy: Policy | None = None) -> SanitizeResult
```
HTTP/FastAPI and CLI adapters will live strictly in `adapters/` and will only be introduced when external processes or language boundaries explicitly require them.

## Alternatives Considered

### 1. FastAPI service from Day 1
- **Pros:** Readily accessible via HTTP from non-Python processes.
- **Cons:** Adds heavy web dependencies (uvicorn, starlette, fastapi), network serialization latency, port management, and test complexity before core privacy invariants are verified.
- **Rejected:** Premature complexity violating KISS and YAGNI.

### 2. CLI-first tool
- **Pros:** Scriptable via shell pipelines.
- **Cons:** High process-spawning overhead per LLM call; inconvenient for high-throughput programmatic usage.
- **Rejected:** In-process library calls provide sub-millisecond execution and direct object typing.

## Consequences
- The core privacy pipeline has zero HTTP framework dependencies.
- Downstream applications can import and run `sanitize()` directly in-process.
- When an HTTP adapter is eventually introduced, it will be a thin wrapper around `sanitize()`.
