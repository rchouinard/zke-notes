---
name: SPA Frontend (TypeScript / Vue 3 / Quasar)
globs: ['spa/**/*.ts', 'spa/**/*.vue', 'spa/**/*.js', 'spa/package.json', 'spa/quasar.config.ts']
alwaysApply: false
---

# SPA Frontend Rules

## Stack

- TypeScript **5.x** with `strict: true` (all strict checks enabled, no `any` escapes)
- Vue **3.5** with Composition API and `<script setup>` syntax exclusively
- Quasar **2.x** (use Quasar components, directives, and plugins — do not re-implement UI primitives)
- Pinia **3.x** for state management
- Axios for HTTP transport
- Vue Router **5.x**

## TypeScript Standards

- `strict: true` is mandatory — never use `@ts-ignore` or `as any`.
- Define explicit TypeScript interfaces or types for all API response shapes in `spa/src/types/` (or `spa/src/models/`).
- Prefer `interface` for object shapes, `type` for unions and computed types.
- Use `const` enums for fixed sets of string/number values shared between modules.
- All Pinia store state, getters, and actions must be explicitly typed.

## Vue / Component Conventions

- Use `<script setup lang="ts">` exclusively — no Options API, no `defineComponent({})` wrapper.
- Props must use `defineProps<{ ... }>()` with explicit TypeScript types.
- Emits must use `defineEmits<{ ... }>()` with explicit types.
- One component per file. File name matches the exported component name (PascalCase, `.vue`).
- Colocate component-specific composables in the same directory as the component.
- Global composables go in `spa/src/composables/`.
- Do NOT put business logic or crypto operations directly in components — delegate to composables or Pinia store actions.

## Quasar Conventions

- Use Quasar's `QLayout`, `QPage`, `QForm`, `QInput`, `QBtn`, etc. for all UI — do not mix in unstyled HTML for interactive elements.
- Use Quasar's `Notify` plugin for user-facing success/error notifications.
- Use Quasar's `Loading` plugin or `QInnerLoading` for async operation feedback (especially during crypto operations).
- Follow Quasar's responsive grid (`QRow`, `QCol`) for layout.

## Pinia Store Organization

- One store per domain concern: `useAuthStore`, `useNoteStore`, `useKeyStore`, etc.
- `useKeyStore` manages all in-memory key material (CryptoKey objects). It must:
    - Hold keys only as non-extractable `CryptoKey` instances, never as raw bytes in state.
    - Expose an `isUnlocked` getter.
    - On `logout()` action, overwrite all key material and reset to null.
- `useAuthStore` manages authentication tokens and current user metadata (but NOT keys).
- `useNoteStore` manages encrypted note list and CRUD operations.

## Crypto Composable

- All Web Crypto logic lives in `spa/src/composables/useCrypto.ts` (or sub-modules under `spa/src/crypto/`).
- Expose clean, well-typed async functions:
    - `generateKeyPair()` — generates a new X25519 ECDH key pair
    - `deriveWrappingKey(password, salt)` — PBKDF2 → AES-256-GCM key
    - `wrapPrivateKey(privateKey, wrappingKey)` — encrypts private key for server storage
    - `unwrapPrivateKey(wrappedKey, wrappingKey)` — decrypts private key from server blob
    - `encryptNote(content, cek)` — AES-256-GCM encrypt note content
    - `decryptNote(ciphertext, cek)` — AES-256-GCM decrypt note content
    - `encryptCEK(cek, recipientPublicKey)` — ECDH + HKDF + AES-GCM wrap the CEK
    - `decryptCEK(wrappedCek, ownPrivateKey, senderPublicKey)` — unwrap the CEK
- Each function must have a JSDoc block describing inputs, outputs, and the algorithm used.

## API Client

- Axios base URL is configured from the environment variable `VITE_API_BASE_URL`.
- Use Axios interceptors to attach the JWT Bearer token to all authenticated requests.
- Define a typed API client layer in `spa/src/api/` with one file per resource (e.g. `notes.ts`, `users.ts`, `auth.ts`). Raw Axios calls must not appear in components or stores.
- Handle 401 responses globally in an interceptor — redirect to login and clear key store.

## Routing & Auth Guards

- Protected routes use a navigation guard that checks `useAuthStore().isAuthenticated` AND `useKeyStore().isUnlocked`.
- If the user is authenticated but keys are not unlocked (e.g., page refresh), redirect to an "unlock vault" screen where the user re-enters their password to re-derive and unwrap their private key.

## Accessibility & UX

- All forms must have proper `label` associations and ARIA attributes.
- Sensitive inputs (passwords, passphrases) use `type="password"` and are never logged or stored in component state beyond immediate use.
