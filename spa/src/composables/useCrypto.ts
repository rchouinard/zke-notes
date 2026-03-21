/**
 * useCrypto — client-side cryptographic primitives for the ZKE Notes SPA.
 *
 * All operations use the Web Crypto API exclusively. No third-party crypto
 * libraries are used. Every function is async; callers must await results.
 *
 * Algorithm reference:
 *  - Key exchange:             X25519 ({ name: 'X25519' } — standalone algorithm, not ECDH namedCurve)
 *  - KDF from ECDH:            HKDF-SHA-256
 *  - Password-based KDF:       PBKDF2-SHA-256, 600 000 iterations
 *  - Symmetric encryption:     AES-256-GCM, random 96-bit IV per operation
 *  - Key encoding:             Base64url, no padding
 */

const PBKDF2_ITERATIONS = 600_000 as const;
const AES_GCM_IV_BYTES = 12 as const;
const PBKDF2_SALT_BYTES = 16 as const;
const AES_KEY_BITS = 256 as const;
const SHARED_KEY_BITS = 256 as const;

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface WrappedKeyMaterial {
  publicKey: string;
  encryptedPrivateKey: string;
  privateKeySalt: string;
  privateKeyIv: string;
}

/**
 * Encodes an ArrayBuffer or TypedArray as a base64url string without padding.
 */
function encodeBase64Url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Narrows a `Uint8Array<ArrayBufferLike>` to the `Uint8Array<ArrayBuffer>`
 * sub-type that the Web Crypto API's `BufferSource` parameter requires.
 *
 * `crypto.getRandomValues` and manual construction both produce arrays backed
 * by a plain `ArrayBuffer`, never a `SharedArrayBuffer`, so the cast is safe.
 * Using `Uint8Array.prototype.slice` (not `subarray`) guarantees a fresh,
 * non-shared backing buffer on the rare path where the source might be shared.
 */
function toBuffer(u8: Uint8Array): Uint8Array<ArrayBuffer> {
  return u8.buffer instanceof ArrayBuffer ? (u8 as Uint8Array<ArrayBuffer>) : u8.slice();
}

/**
 * Decodes a base64url string (with or without padding) into a Uint8Array.
 *
 * @throws {Error} if the input contains characters outside the base64url alphabet.
 */
function decodeBase64Url(input: string): Uint8Array<ArrayBuffer> {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generates a cryptographically random PBKDF2 salt.
 *
 * @returns A {@link PBKDF2_SALT_BYTES}-byte Uint8Array.
 */
function generateSalt(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTES));
}

/**
 * Generates a cryptographically random AES-GCM IV / nonce.
 *
 * @returns A {@link AES_GCM_IV_BYTES}-byte Uint8Array.
 */
function generateIv(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
}

/**
 * Generates a new X25519 key pair.
 *
 * Uses the standalone `{ name: 'X25519' }` algorithm identifier, which is the
 * current Web Crypto standard (Chrome 133+, Firefox 130+, Safari 17+, Node 22+).
 *
 * - The public key is exportable (SPKI) so it can be sent to the server.
 * - The private key is marked extractable so it can be wrapped by `wrapPrivateKey`.
 *   It is never exported as raw bytes — only as an AES-GCM-wrapped PKCS#8 blob.
 *
 * @throws {Error} if the Web Crypto API rejects key generation.
 */
async function generateKeyPair(): Promise<KeyPair> {
  try {
    const keyPair = (await crypto.subtle.generateKey(
      { name: 'X25519' },
      /*
       * extractable must be true so that wrapKey('pkcs8', ...) can serialise
       * the private key into the AES-GCM wrapper. The raw private key bytes
       * are never exposed — the only export path is through wrapPrivateKey.
       */
      true,
      ['deriveKey', 'deriveBits'],
    )) as CryptoKeyPair;
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
  } catch (err) {
    throw new Error(`Key pair generation failed: ${String(err)}`);
  }
}

/**
 * Imports a raw password string as a PBKDF2 key material object.
 *
 * @param password - The user's plaintext password.
 */
async function importPasswordKey(password: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    /* extractable */ false,
    ['deriveKey'],
  );
}

/**
 * Derives an AES-256-GCM wrapping key from a password and salt using
 * PBKDF2-SHA-256 with {@link PBKDF2_ITERATIONS} iterations.
 *
 * @param password - The user's plaintext password.
 * @param salt     - A {@link PBKDF2_SALT_BYTES}-byte salt (Uint8Array or base64url).
 *
 * @throws {Error} if key derivation fails.
 */
async function deriveWrappingKey(password: string, salt: Uint8Array | string): Promise<CryptoKey> {
  try {
    const saltBytes = typeof salt === 'string' ? decodeBase64Url(salt) : salt;
    const passwordKey = await importPasswordKey(password);

    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: toBuffer(saltBytes),
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256',
      },
      passwordKey,
      { name: 'AES-GCM', length: AES_KEY_BITS },
      /* extractable */ false,
      ['wrapKey', 'unwrapKey'],
    );
  } catch (err) {
    throw new Error(`Wrapping key derivation failed: ${String(err)}`);
  }
}

/**
 * Wraps (encrypts) a private key using AES-256-GCM.
 *
 * The Web Crypto API appends the 16-byte GCM authentication tag to the
 * ciphertext, producing a single `ciphertext ‖ tag` blob — matching the
 * format used by the PHP `UserCryptoGenerator`.
 *
 * @param privateKey   - The X25519 private key to wrap.
 * @param wrappingKey  - An AES-256-GCM key derived via {@link deriveWrappingKey}.
 * @param iv           - A {@link AES_GCM_IV_BYTES}-byte IV (Uint8Array or base64url).
 *
 * @returns The encrypted key material as a base64url string.
 *
 * @throws {Error} if wrapping fails.
 */
async function wrapPrivateKey(
  privateKey: CryptoKey,
  wrappingKey: CryptoKey,
  iv: Uint8Array | string,
): Promise<string> {
  try {
    const ivBytes = typeof iv === 'string' ? decodeBase64Url(iv) : iv;

    const wrapped = await crypto.subtle.wrapKey('pkcs8', privateKey, wrappingKey, {
      name: 'AES-GCM',
      iv: toBuffer(ivBytes),
    });

    return encodeBase64Url(wrapped);
  } catch (err) {
    throw new Error(`Private key wrapping failed: ${String(err)}`);
  }
}

/**
 * Unwraps (decrypts) an encrypted private key using AES-256-GCM.
 *
 * The resulting private key is non-extractable and marked for
 * `['deriveKey', 'deriveBits']` usage.
 *
 * @param encryptedPrivateKey - Base64url-encoded `ciphertext ‖ tag` blob.
 * @param wrappingKey         - An AES-256-GCM key derived via {@link deriveWrappingKey}.
 * @param iv                  - The {@link AES_GCM_IV_BYTES}-byte IV used during wrapping
 *                              (Uint8Array or base64url).
 *
 * @returns The unwrapped X25519 private key as a non-extractable CryptoKey.
 *
 * @throws {Error} if the ciphertext is tampered with or the wrapping key is wrong
 *                 (GCM tag authentication failure), or if the format is invalid.
 */
async function unwrapPrivateKey(
  encryptedPrivateKey: string,
  wrappingKey: CryptoKey,
  iv: Uint8Array | string,
): Promise<CryptoKey> {
  try {
    const ivBytes = typeof iv === 'string' ? decodeBase64Url(iv) : iv;
    const ciphertext = decodeBase64Url(encryptedPrivateKey);

    return await crypto.subtle.unwrapKey(
      'pkcs8',
      toBuffer(ciphertext),
      wrappingKey,
      { name: 'AES-GCM', iv: toBuffer(ivBytes) },
      { name: 'X25519' },
      /* extractable */ false,
      ['deriveKey', 'deriveBits'],
    );
  } catch (err) {
    throw new Error(`Private key unwrapping failed: ${String(err)}`);
  }
}

/**
 * Exports a CryptoKey public key as a base64url-encoded SPKI blob.
 *
 * @throws {Error} if export fails.
 */
async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  try {
    const spki = await crypto.subtle.exportKey('spki', publicKey);
    return encodeBase64Url(spki);
  } catch (err) {
    throw new Error(`Public key export failed: ${String(err)}`);
  }
}

/**
 * Imports a base64url-encoded SPKI public key for use in ECDH key derivation.
 *
 * @param base64url - The base64url-encoded SPKI public key.
 *
 * @returns A non-extractable CryptoKey usable for `['deriveKey', 'deriveBits']`.
 *
 * @throws {Error} if the input is not a valid X25519 SPKI key.
 */
async function importPublicKey(base64url: string): Promise<CryptoKey> {
  try {
    const spki = decodeBase64Url(base64url);
    return await crypto.subtle.importKey(
      'spki',
      toBuffer(spki),
      { name: 'X25519' },
      /* extractable */ false,
      [],
    );
  } catch (err) {
    throw new Error(`Public key import failed: ${String(err)}`);
  }
}

/**
 * Generates a random AES-256-GCM content encryption key (CEK) for a note.
 *
 * The key is non-extractable for direct use but must be exported via
 * {@link exportContentKey} before it can be wrapped and stored.
 *
 * @throws {Error} if key generation fails.
 */
async function generateContentKey(): Promise<CryptoKey> {
  try {
    return await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: AES_KEY_BITS },
      /* extractable — must be exported for wrapping */ true,
      ['encrypt', 'decrypt'],
    );
  } catch (err) {
    throw new Error(`Content key generation failed: ${String(err)}`);
  }
}

/**
 * Encrypts a plaintext string with an AES-256-GCM key.
 *
 * A fresh random IV is generated for every call.
 *
 * @param plaintext - The string to encrypt (UTF-8 encoded).
 * @param key       - An AES-256-GCM CryptoKey.
 *
 * @returns An object containing the base64url-encoded ciphertext and IV.
 *
 * @throws {Error} if encryption fails.
 */
async function encryptContent(
  plaintext: string,
  key: CryptoKey,
): Promise<{ ciphertext: string; iv: string }> {
  try {
    const iv = generateIv();
    const encoded = new TextEncoder().encode(plaintext);

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toBuffer(iv) },
      key,
      toBuffer(encoded),
    );

    return {
      ciphertext: encodeBase64Url(ciphertext),
      iv: encodeBase64Url(iv),
    };
  } catch (err) {
    throw new Error(`Content encryption failed: ${String(err)}`);
  }
}

/**
 * Decrypts a base64url-encoded AES-256-GCM ciphertext back to a UTF-8 string.
 *
 * @param ciphertext - Base64url-encoded `ciphertext ‖ GCM tag` blob.
 * @param iv         - Base64url-encoded IV used during encryption.
 * @param key        - The AES-256-GCM CryptoKey.
 *
 * @throws {Error} if decryption or authentication fails (wrong key / tampered data).
 */
async function decryptContent(ciphertext: string, iv: string, key: CryptoKey): Promise<string> {
  try {
    const ivBytes = decodeBase64Url(iv);
    const ciphertextBytes = decodeBase64Url(ciphertext);

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toBuffer(ivBytes) },
      key,
      toBuffer(ciphertextBytes),
    );

    return new TextDecoder().decode(plaintext);
  } catch (err) {
    throw new Error(`Content decryption failed: ${String(err)}`);
  }
}

/**
 * Exports a content encryption key (CEK) as raw bytes and encodes it as base64url.
 *
 * @throws {Error} if the key is non-extractable or export fails.
 */
async function exportContentKey(key: CryptoKey): Promise<string> {
  try {
    const raw = await crypto.subtle.exportKey('raw', key);
    return encodeBase64Url(raw);
  } catch (err) {
    throw new Error(`Content key export failed: ${String(err)}`);
  }
}

/**
 * Imports a raw base64url-encoded AES-256-GCM content encryption key.
 *
 * @param base64url - The base64url-encoded raw key bytes.
 *
 * @throws {Error} if the input is not a valid 256-bit AES key.
 */
async function importContentKey(base64url: string): Promise<CryptoKey> {
  try {
    const raw = decodeBase64Url(base64url);
    return await crypto.subtle.importKey(
      'raw',
      toBuffer(raw),
      { name: 'AES-GCM', length: AES_KEY_BITS },
      /* extractable */ true,
      ['encrypt', 'decrypt'],
    );
  } catch (err) {
    throw new Error(`Content key import failed: ${String(err)}`);
  }
}

/**
 * Derives an ECDH shared secret between a local private key and a remote public
 * key, then passes it through HKDF-SHA-256 to produce an AES-256-GCM key
 * suitable for wrapping a note's CEK.
 *
 * @param localPrivateKey  - The caller's X25519 private key.
 * @param remotePublicKey  - The recipient's X25519 public key.
 *
 * @throws {Error} if key derivation fails.
 */
async function deriveSharedKey(
  localPrivateKey: CryptoKey,
  remotePublicKey: CryptoKey,
): Promise<CryptoKey> {
  try {
    return await crypto.subtle.deriveKey(
      {
        name: 'X25519',
        public: remotePublicKey,
      },
      localPrivateKey,
      { name: 'AES-GCM', length: SHARED_KEY_BITS },
      /* extractable */ false,
      ['wrapKey', 'unwrapKey'],
    );
  } catch (err) {
    throw new Error(`Shared key derivation failed: ${String(err)}`);
  }
}

/**
 * Wraps a content encryption key (CEK) with an AES-256-GCM key.
 *
 * Used both for owner storage (wrapping the CEK with the owner's personal key)
 * and for note sharing (wrapping the CEK with an ECDH-derived shared key).
 *
 * A fresh random IV is generated for every call.
 *
 * @param contentKey  - The AES-256-GCM CEK to wrap.
 * @param wrappingKey - The AES-256-GCM key to wrap with.
 *
 * @returns An object containing the base64url-encoded wrapped key and IV.
 *
 * @throws {Error} if wrapping fails.
 */
async function wrapContentKey(
  contentKey: CryptoKey,
  wrappingKey: CryptoKey,
): Promise<{ encryptedContentKey: string; iv: string }> {
  try {
    const iv = generateIv();

    const wrapped = await crypto.subtle.wrapKey('raw', contentKey, wrappingKey, {
      name: 'AES-GCM',
      iv: toBuffer(iv),
    });

    return {
      encryptedContentKey: encodeBase64Url(wrapped),
      iv: encodeBase64Url(iv),
    };
  } catch (err) {
    throw new Error(`Content key wrapping failed: ${String(err)}`);
  }
}

/**
 * Unwraps a base64url-encoded CEK that was previously wrapped with an AES-256-GCM key.
 *
 * @param encryptedContentKey - Base64url-encoded wrapped key blob.
 * @param iv                  - Base64url-encoded IV used during wrapping.
 * @param wrappingKey         - The AES-256-GCM key to unwrap with.
 *
 * @returns The unwrapped AES-256-GCM CEK.
 *
 * @throws {Error} if authentication fails or the wrapping key is incorrect.
 */
async function unwrapContentKey(
  encryptedContentKey: string,
  iv: string,
  wrappingKey: CryptoKey,
): Promise<CryptoKey> {
  try {
    const ivBytes = decodeBase64Url(iv);
    const wrapped = decodeBase64Url(encryptedContentKey);

    return await crypto.subtle.unwrapKey(
      'raw',
      toBuffer(wrapped),
      wrappingKey,
      { name: 'AES-GCM', iv: toBuffer(ivBytes) },
      { name: 'AES-GCM', length: AES_KEY_BITS },
      /* extractable */ true,
      ['encrypt', 'decrypt'],
    );
  } catch (err) {
    throw new Error(`Content key unwrapping failed: ${String(err)}`);
  }
}

/**
 * Performs all client-side cryptographic steps required for user registration.
 *
 * Sequence:
 *  1. Generate an X25519 key pair.
 *  2. Generate a random PBKDF2 salt and AES-GCM IV.
 *  3. Derive an AES-256-GCM wrapping key from the password via PBKDF2.
 *  4. Wrap the private key with the wrapping key.
 *  5. Export the public key as a base64url SPKI string.
 *
 * The returned `WrappedKeyMaterial` fields map directly to the `POST /api/users`
 * request body. The live `KeyPair` is returned separately so the caller can
 * populate the key store without a second derivation round-trip.
 *
 * @param password - The user's chosen password (never transmitted after this call).
 *
 * @throws {Error} if any cryptographic step fails.
 */
async function prepareRegistrationKeys(
  password: string,
): Promise<{ material: WrappedKeyMaterial; keyPair: KeyPair }> {
  const keyPair = await generateKeyPair();
  const salt = generateSalt();
  const iv = generateIv();

  const wrappingKey = await deriveWrappingKey(password, salt);
  const encryptedPrivateKey = await wrapPrivateKey(keyPair.privateKey, wrappingKey, iv);
  const publicKey = await exportPublicKey(keyPair.publicKey);

  return {
    material: {
      publicKey,
      encryptedPrivateKey,
      privateKeySalt: encodeBase64Url(salt),
      privateKeyIv: encodeBase64Url(iv),
    },
    keyPair,
  };
}

/**
 * Performs all client-side cryptographic steps required at login to recover
 * the user's private key from the server-supplied wrapped key material.
 *
 * Sequence:
 *  1. Derive the AES-256-GCM wrapping key from the password and the stored salt.
 *  2. Unwrap the private key — GCM tag verification implicitly authenticates
 *     the password; a wrong password will cause this step to throw.
 *  3. Import the stored public key.
 *
 * @param password            - The user's password.
 * @param encryptedPrivateKey - Base64url blob from the server.
 * @param privateKeySalt      - Base64url salt from the server.
 * @param privateKeyIv        - Base64url IV from the server.
 * @param publicKeySpki       - Base64url SPKI public key from the server.
 *
 * @throws {Error} if the password is wrong or any cryptographic step fails.
 */
async function recoverKeyPair(
  password: string,
  encryptedPrivateKey: string,
  privateKeySalt: string,
  privateKeyIv: string,
  publicKeySpki: string,
): Promise<KeyPair> {
  const wrappingKey = await deriveWrappingKey(password, privateKeySalt);
  const privateKey = await unwrapPrivateKey(encryptedPrivateKey, wrappingKey, privateKeyIv);
  const publicKey = await importPublicKey(publicKeySpki);

  return { publicKey, privateKey };
}

/**
 * Returns all crypto primitives and high-level helpers as a plain object.
 *
 * Usage:
 * ```ts
 * const crypto = useCrypto();
 * const { material, keyPair } = await crypto.prepareRegistrationKeys(password);
 * ```
 */
export function useCrypto() {
  return {
    // Encoding
    encodeBase64Url,
    decodeBase64Url,

    // Random material
    generateSalt,
    generateIv,

    // Key pair
    generateKeyPair,
    exportPublicKey,
    importPublicKey,

    // Password-based wrapping
    deriveWrappingKey,
    wrapPrivateKey,
    unwrapPrivateKey,

    // Note content encryption
    generateContentKey,
    encryptContent,
    decryptContent,

    // Content key wrapping / sharing
    exportContentKey,
    importContentKey,
    deriveSharedKey,
    wrapContentKey,
    unwrapContentKey,

    // High-level composite helpers
    prepareRegistrationKeys,
    recoverKeyPair,
  } as const;
}
