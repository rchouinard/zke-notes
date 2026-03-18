---
name: Zero-Knowledge Encryption Design
alwaysApply: true
---

# Zero-Knowledge Encryption Rules

## Cryptographic Model

### User Key Pair (Asymmetric)

- Each user generates an **X25519** (ECDH) key pair in the browser on registration.
- The **public key** is uploaded to and stored by the server (plaintext, base64url-encoded).
- The **private key** never leaves the browser unencrypted. It is wrapped (encrypted) with a key derived from the user's password using PBKDF2, then stored server-side as an opaque blob.
- Private key derivation: `PBKDF2(password, salt, 600_000 iterations, SHA-256) → AES-256-GCM wrapping key → encrypt(privateKey)`.

### Note Encryption (Symmetric)

- Each note has a unique random **AES-256-GCM** content encryption key (CEK).
- Note content (title + body) is encrypted with the CEK before any transmission.
- The CEK is encrypted ("wrapped") with the owner's X25519-derived shared secret (ECDH + HKDF) and stored alongside the ciphertext.

### Note Sharing (Asymmetric Key Transport)

- To share a note, the sender derives an ECDH shared secret with the recipient's public key.
- The sender wraps the note's CEK with `ECDH(senderPrivate, recipientPublic) → HKDF → AES-256-GCM`.
- The wrapped CEK is stored as a `NoteShare` record on the server alongside the recipient's user ID.
- The server never sees the unwrapped CEK or any plaintext.

### Algorithm Reference

| Purpose                       | Algorithm                                    |
| ----------------------------- | -------------------------------------------- |
| Key exchange                  | X25519 (ECDH, `namedCurve: "X25519"`)        |
| Key derivation from ECDH      | HKDF-SHA-256                                 |
| Password-based key derivation | PBKDF2-SHA-256, ≥ 600 000 iterations         |
| Symmetric encryption          | AES-256-GCM (random 96-bit IV per operation) |
| Key encoding                  | Base64url (no padding)                       |

## SPA Crypto Rules

- All crypto operations MUST use the **Web Crypto API** (`window.crypto.subtle`). Never use third-party crypto libraries for core operations.
- IVs/nonces are always randomly generated per-encryption; never reuse.
- Crypto operations are async — always `await` them; never block.
- Wrap all `subtle` calls in try/catch and surface meaningful errors to the user.
- Key material in memory (CryptoKey objects) must not be serialized into Pinia state or `localStorage` as raw bytes — use non-extractable CryptoKeys where possible and hold them only in a dedicated key-management store.
- On logout, explicitly zero/clear key material from memory stores.

## API / Server Rules

- The API MUST NOT implement any encryption or decryption logic.
- The API stores these opaque blobs as-is: `encryptedPrivateKey`, `publicKey`, `encryptedContent`, `encryptedContentKey`.
- Never log or expose ciphertext content in error messages or profiler output.
- Validate that ciphertext/key fields are valid base64url strings of acceptable lengths, but perform no further inspection.
- The API must NOT expose a `/decrypt` or `/encrypt` endpoint of any kind.
