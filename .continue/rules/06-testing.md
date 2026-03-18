---
name: Testing Standards
alwaysApply: true
---

# Testing Rules

## API (PHPUnit / Symfony)

- Tests live in `api/tests/`. Unit tests in `api/tests/Unit/`, functional/integration tests in `api/tests/Functional/`.
- Use Symfony's `KernelTestCase` for integration tests and `WebTestCase`/`ApiTestCase` (API Platform) for functional API tests.
- Use a separate test database (configured via `DATABASE_URL` in `.env.test`).
- Test all state processors, voters, and custom repository methods.
- For crypto-adjacent code (e.g., base64url validation), test that the API correctly accepts valid blobs and rejects invalid ones — do NOT test actual decryption server-side.
- Use PHPUnit data providers for input validation boundary tests.
- Aim for 100% coverage of security-critical paths (voters, access control, input validation).

## SPA (Vitest / Vue Test Utils)

- Tests live in `spa/src/__tests__/` or colocated as `ComponentName.spec.ts`.
- Use **Vitest** and **@vue/test-utils** for component and composable testing.
- The `useCrypto` composable must have comprehensive unit tests covering every exported function, including:
    - Key generation produces expected key type and algorithm.
    - Encrypt → Decrypt round trips produce original plaintext.
    - Wrong key decryption throws/rejects.
    - IV uniqueness (statistical test: 100 encryptions produce 100 distinct IVs).
- Pinia stores are tested in isolation using `createPinia()` from `@pinia/testing`.
- Mock Axios in store tests using `vi.mock` — do not make real HTTP calls in unit tests.
- Do not use `any` in test code — maintain the same TypeScript strictness as production code.

## General

- Tests must not contain hardcoded passwords, keys, or secrets — use per-test randomly generated values.
- Never commit `.env.test` with real credentials to the repository.
