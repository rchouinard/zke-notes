/**
 * useCrypto composable — unit tests.
 *
 * Tests cover:
 *  - encodeBase64Url / decodeBase64Url round-trips and edge cases
 *  - generateSalt / generateIv output length and uniqueness
 *  - generateKeyPair algorithm and extractability
 *  - exportPublicKey / importPublicKey round-trip
 *  - deriveWrappingKey accepts both Uint8Array and base64url salt
 *  - wrapPrivateKey / unwrapPrivateKey round-trip
 *  - unwrapPrivateKey rejects on wrong wrapping key
 *  - generateContentKey algorithm and extractability
 *  - encryptContent / decryptContent round-trip
 *  - decryptContent rejects on wrong key
 *  - encryptContent produces unique IVs across 100 calls
 *  - exportContentKey / importContentKey round-trip
 *  - deriveSharedKey produces symmetric shared secrets
 *  - wrapContentKey / unwrapContentKey round-trip
 *  - unwrapContentKey rejects on wrong wrapping key
 *  - prepareRegistrationKeys structure and internal consistency
 *  - recoverKeyPair succeeds with correct password
 *  - recoverKeyPair rejects with wrong password
 */

import { describe, it, expect } from 'vitest';
import { useCrypto } from '../composables/useCrypto';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generates a random ASCII password for use within a single test. */
function randomPassword(): string {
  return `pw-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

describe('encodeBase64Url / decodeBase64Url', () => {
  const { encodeBase64Url, decodeBase64Url } = useCrypto();

  it('round-trips arbitrary bytes', () => {
    const original = crypto.getRandomValues(new Uint8Array(64));
    const encoded = encodeBase64Url(original);
    const decoded = decodeBase64Url(encoded);
    expect(decoded).toEqual(original);
  });

  it('produces no padding characters', () => {
    // Test all three padding cases (length mod 3 = 0, 1, 2).
    for (const len of [9, 10, 11]) {
      const bytes = crypto.getRandomValues(new Uint8Array(len));
      expect(encodeBase64Url(bytes)).not.toMatch(/=/);
    }
  });

  it('replaces + with - and / with _', () => {
    const encoded = encodeBase64Url(crypto.getRandomValues(new Uint8Array(64)));
    expect(encoded).not.toMatch(/[+/]/);
  });

  it('accepts an ArrayBuffer as input', () => {
    const buf = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const encoded = encodeBase64Url(buf);
    expect(typeof encoded).toBe('string');
    expect(encoded.length).toBeGreaterThan(0);
  });

  it('handles a zero-length input', () => {
    expect(encodeBase64Url(new Uint8Array(0))).toBe('');
    expect(decodeBase64Url('')).toEqual(new Uint8Array(0));
  });

  it('decodes strings that already have padding', () => {
    const original = crypto.getRandomValues(new Uint8Array(32));
    // Manually add padding to simulate a padded base64url string.
    const padded = btoa(String.fromCharCode(...original))
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
    const decoded = decodeBase64Url(padded);
    expect(decoded).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// Random material generation
// ---------------------------------------------------------------------------

describe('generateSalt', () => {
  const { generateSalt } = useCrypto();

  it('returns exactly 16 bytes', () => {
    expect(generateSalt()).toHaveLength(16);
  });

  it('produces distinct values on successive calls', () => {
    const a = generateSalt();
    const b = generateSalt();
    expect(a).not.toEqual(b);
  });
});

describe('generateIv', () => {
  const { generateIv } = useCrypto();

  it('returns exactly 12 bytes', () => {
    expect(generateIv()).toHaveLength(12);
  });

  it('produces distinct values on successive calls', () => {
    const a = generateIv();
    const b = generateIv();
    expect(a).not.toEqual(b);
  });
});

// ---------------------------------------------------------------------------
// Key pair
// ---------------------------------------------------------------------------

describe('generateKeyPair', () => {
  const { generateKeyPair } = useCrypto();

  it('returns a CryptoKeyPair with the X25519 algorithm', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    expect(publicKey.algorithm.name).toBe('X25519');
    expect(privateKey.algorithm.name).toBe('X25519');
  });

  it('private key is extractable (required for wrapKey)', async () => {
    // The private key must be extractable so it can be serialised by
    // wrapPrivateKey into an AES-GCM-wrapped PKCS#8 blob. Raw bytes are
    // never exposed — the unwrapped key returned by unwrapPrivateKey is
    // non-extractable.
    const { privateKey } = await generateKeyPair();
    expect(privateKey.extractable).toBe(true);
  });

  it('public key is extractable', async () => {
    const { publicKey } = await generateKeyPair();
    expect(publicKey.extractable).toBe(true);
  });

  it('private key has deriveKey and deriveBits usages', async () => {
    const { privateKey } = await generateKeyPair();
    expect(privateKey.usages).toContain('deriveKey');
    expect(privateKey.usages).toContain('deriveBits');
  });
});

// ---------------------------------------------------------------------------
// Public key export / import
// ---------------------------------------------------------------------------

describe('exportPublicKey / importPublicKey', () => {
  const { generateKeyPair, exportPublicKey, importPublicKey } = useCrypto();

  it('exports a non-empty base64url string', async () => {
    const { publicKey } = await generateKeyPair();
    const exported = await exportPublicKey(publicKey);
    expect(typeof exported).toBe('string');
    expect(exported.length).toBeGreaterThan(0);
    expect(exported).not.toMatch(/[+/=]/);
  });

  it('imported key has the correct algorithm', async () => {
    const { publicKey } = await generateKeyPair();
    const exported = await exportPublicKey(publicKey);
    const imported = await importPublicKey(exported);
    expect(imported.algorithm.name).toBe('X25519');
  });

  it('imported key is not extractable', async () => {
    const { publicKey } = await generateKeyPair();
    const exported = await exportPublicKey(publicKey);
    const imported = await importPublicKey(exported);
    expect(imported.extractable).toBe(false);
  });

  it('rejects an invalid base64url string', async () => {
    await expect(importPublicKey('not-a-valid-key!!!')).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Wrapping key derivation
// ---------------------------------------------------------------------------

describe('deriveWrappingKey', () => {
  const { deriveWrappingKey, generateSalt, encodeBase64Url } = useCrypto();

  it('returns an AES-GCM CryptoKey', async () => {
    const key = await deriveWrappingKey(randomPassword(), generateSalt());
    expect(key.algorithm.name).toBe('AES-GCM');
  });

  it('has wrapKey and unwrapKey usages', async () => {
    const key = await deriveWrappingKey(randomPassword(), generateSalt());
    expect(key.usages).toContain('wrapKey');
    expect(key.usages).toContain('unwrapKey');
  });

  it('is not extractable', async () => {
    const key = await deriveWrappingKey(randomPassword(), generateSalt());
    expect(key.extractable).toBe(false);
  });

  it('accepts a base64url-encoded salt string', async () => {
    const salt = generateSalt();
    const saltB64 = encodeBase64Url(salt);
    const keyFromBytes = await deriveWrappingKey(randomPassword(), salt);
    const keyFromString = await deriveWrappingKey(randomPassword(), saltB64);
    // Both calls should succeed and return CryptoKey objects.
    expect(keyFromBytes.algorithm.name).toBe('AES-GCM');
    expect(keyFromString.algorithm.name).toBe('AES-GCM');
  });
});

// ---------------------------------------------------------------------------
// Private key wrapping / unwrapping
// ---------------------------------------------------------------------------

describe('wrapPrivateKey / unwrapPrivateKey', () => {
  const {
    generateKeyPair,
    generateSalt,
    generateIv,
    deriveWrappingKey,
    wrapPrivateKey,
    unwrapPrivateKey,
    exportPublicKey,
    importPublicKey,
  } = useCrypto();

  async function makeWrappingKey(password: string) {
    return deriveWrappingKey(password, generateSalt());
  }

  it('wrap → unwrap round-trip returns a usable private key', async () => {
    const password = randomPassword();
    const { privateKey, publicKey } = await generateKeyPair();
    const wrappingKey = await makeWrappingKey(password);
    const iv = generateIv();

    const encryptedPrivateKey = await wrapPrivateKey(privateKey, wrappingKey, iv);
    const recovered = await unwrapPrivateKey(encryptedPrivateKey, wrappingKey, iv);

    expect(recovered.algorithm.name).toBe('X25519');
    expect(recovered.extractable).toBe(false);
    expect(recovered.usages).toContain('deriveKey');

    // Verify the recovered key is functionally correct by deriving a shared
    // secret with the matching public key — if the key is corrupted this throws.
    const peerPublicKey = await importPublicKey(await exportPublicKey(publicKey));
    await expect(
      crypto.subtle.deriveBits({ name: 'X25519', public: peerPublicKey }, recovered, 256),
    ).resolves.not.toThrow();
  });

  it('unwrapPrivateKey rejects when the wrapping key is wrong', async () => {
    const { privateKey } = await generateKeyPair();
    const correctKey = await makeWrappingKey(randomPassword());
    const wrongKey = await makeWrappingKey(randomPassword());
    const iv = generateIv();

    const encryptedPrivateKey = await wrapPrivateKey(privateKey, correctKey, iv);
    await expect(unwrapPrivateKey(encryptedPrivateKey, wrongKey, iv)).rejects.toThrow();
  });

  it('accepts a base64url IV string', async () => {
    const { privateKey } = await generateKeyPair();
    const wrappingKey = await makeWrappingKey(randomPassword());
    const iv = generateIv();
    const { encodeBase64Url } = useCrypto();
    const ivB64 = encodeBase64Url(iv);

    const encryptedPrivateKey = await wrapPrivateKey(privateKey, wrappingKey, ivB64);
    const recovered = await unwrapPrivateKey(encryptedPrivateKey, wrappingKey, ivB64);
    expect(recovered.algorithm.name).toBe('X25519');
  });
});

// ---------------------------------------------------------------------------
// Note content encryption
// ---------------------------------------------------------------------------

describe('generateContentKey', () => {
  const { generateContentKey } = useCrypto();

  it('returns an AES-GCM CryptoKey', async () => {
    const key = await generateContentKey();
    expect(key.algorithm.name).toBe('AES-GCM');
    expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
  });

  it('is extractable', async () => {
    const key = await generateContentKey();
    expect(key.extractable).toBe(true);
  });

  it('has encrypt and decrypt usages', async () => {
    const key = await generateContentKey();
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');
  });
});

describe('encryptContent / decryptContent', () => {
  const { generateContentKey, encryptContent, decryptContent } = useCrypto();

  it('round-trips a plaintext string', async () => {
    const key = await generateContentKey();
    const plaintext = 'Hello, zero-knowledge world! 🔐';
    const { ciphertext, iv } = await encryptContent(plaintext, key);
    const recovered = await decryptContent(ciphertext, iv, key);
    expect(recovered).toBe(plaintext);
  });

  it('round-trips an empty string', async () => {
    const key = await generateContentKey();
    const { ciphertext, iv } = await encryptContent('', key);
    const recovered = await decryptContent(ciphertext, iv, key);
    expect(recovered).toBe('');
  });

  it('ciphertext is a non-empty base64url string', async () => {
    const key = await generateContentKey();
    const { ciphertext } = await encryptContent('test', key);
    expect(typeof ciphertext).toBe('string');
    expect(ciphertext.length).toBeGreaterThan(0);
    expect(ciphertext).not.toMatch(/[+/=]/);
  });

  it('decryptContent rejects when using the wrong key', async () => {
    const key = await generateContentKey();
    const wrongKey = await generateContentKey();
    const { ciphertext, iv } = await encryptContent('secret', key);
    await expect(decryptContent(ciphertext, iv, wrongKey)).rejects.toThrow();
  });

  it('produces unique IVs across 100 encryptions', async () => {
    const key = await generateContentKey();
    const ivSet = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const { iv } = await encryptContent('data', key);
      ivSet.add(iv);
    }
    expect(ivSet.size).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// Content key export / import
// ---------------------------------------------------------------------------

describe('exportContentKey / importContentKey', () => {
  const { generateContentKey, exportContentKey, importContentKey, encryptContent, decryptContent } =
    useCrypto();

  it('exports a non-empty base64url string', async () => {
    const key = await generateContentKey();
    const exported = await exportContentKey(key);
    expect(typeof exported).toBe('string');
    expect(exported.length).toBeGreaterThan(0);
    expect(exported).not.toMatch(/[+/=]/);
  });

  it('export → import produces a functionally equivalent key', async () => {
    const key = await generateContentKey();
    const exported = await exportContentKey(key);
    const imported = await importContentKey(exported);

    const plaintext = 'round-trip test';
    const { ciphertext, iv } = await encryptContent(plaintext, key);
    const recovered = await decryptContent(ciphertext, iv, imported);
    expect(recovered).toBe(plaintext);
  });
});

// ---------------------------------------------------------------------------
// Shared key derivation
// ---------------------------------------------------------------------------

describe('deriveSharedKey', () => {
  const { generateKeyPair, deriveSharedKey, importPublicKey, exportPublicKey } = useCrypto();

  it('derives the same shared key from both sides', async () => {
    const alice = await generateKeyPair();
    const bob = await generateKeyPair();

    const alicePublicImported = await importPublicKey(await exportPublicKey(alice.publicKey));
    const bobPublicImported = await importPublicKey(await exportPublicKey(bob.publicKey));

    const aliceShared = await deriveSharedKey(alice.privateKey, bobPublicImported);
    const bobShared = await deriveSharedKey(bob.privateKey, alicePublicImported);

    // Both shared keys should be AES-GCM keys. We verify symmetry by using
    // Alice's key to wrap and Bob's key to unwrap.
    const { generateContentKey, wrapContentKey, unwrapContentKey } = useCrypto();
    const cek = await generateContentKey();
    const { encryptedContentKey, iv } = await wrapContentKey(cek, aliceShared);
    const unwrapped = await unwrapContentKey(encryptedContentKey, iv, bobShared);

    expect(unwrapped.algorithm.name).toBe('AES-GCM');
  });

  it('returns an AES-GCM key', async () => {
    const alice = await generateKeyPair();
    const bob = await generateKeyPair();
    const bobPublic = await importPublicKey(await exportPublicKey(bob.publicKey));
    const shared = await deriveSharedKey(alice.privateKey, bobPublic);
    expect(shared.algorithm.name).toBe('AES-GCM');
  });

  it('is not extractable', async () => {
    const alice = await generateKeyPair();
    const bob = await generateKeyPair();
    const bobPublic = await importPublicKey(await exportPublicKey(bob.publicKey));
    const shared = await deriveSharedKey(alice.privateKey, bobPublic);
    expect(shared.extractable).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Content key wrapping / unwrapping
// ---------------------------------------------------------------------------

describe('wrapContentKey / unwrapContentKey', () => {
  const { generateContentKey, deriveWrappingKey, generateSalt, wrapContentKey, unwrapContentKey } =
    useCrypto();

  async function makePairAndWrapper() {
    const cek = await generateContentKey();
    const wrappingKey = await deriveWrappingKey(randomPassword(), generateSalt());
    return { cek, wrappingKey };
  }

  it('wrap → unwrap round-trip returns a usable key', async () => {
    const { cek, wrappingKey } = await makePairAndWrapper();
    const { encryptedContentKey, iv } = await wrapContentKey(cek, wrappingKey);
    const unwrapped = await unwrapContentKey(encryptedContentKey, iv, wrappingKey);
    expect(unwrapped.algorithm.name).toBe('AES-GCM');
    expect(unwrapped.usages).toContain('encrypt');
    expect(unwrapped.usages).toContain('decrypt');
  });

  it('produces unique IVs across successive wraps', async () => {
    const { cek, wrappingKey } = await makePairAndWrapper();
    const ivSet = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const { iv } = await wrapContentKey(cek, wrappingKey);
      ivSet.add(iv);
    }
    expect(ivSet.size).toBe(20);
  });

  it('unwrapContentKey rejects with the wrong wrapping key', async () => {
    const { cek, wrappingKey } = await makePairAndWrapper();
    const wrongKey = await deriveWrappingKey(randomPassword(), generateSalt());
    const { encryptedContentKey, iv } = await wrapContentKey(cek, wrappingKey);
    await expect(unwrapContentKey(encryptedContentKey, iv, wrongKey)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// High-level composite helpers
// ---------------------------------------------------------------------------

describe('prepareRegistrationKeys', () => {
  const { prepareRegistrationKeys } = useCrypto();

  it('returns all required WrappedKeyMaterial fields', async () => {
    const { material } = await prepareRegistrationKeys(randomPassword());
    expect(typeof material.publicKey).toBe('string');
    expect(typeof material.encryptedPrivateKey).toBe('string');
    expect(typeof material.privateKeySalt).toBe('string');
    expect(typeof material.privateKeyIv).toBe('string');
  });

  it('all material fields are non-empty base64url strings', async () => {
    const { material } = await prepareRegistrationKeys(randomPassword());
    for (const field of Object.values(material)) {
      expect(field.length).toBeGreaterThan(0);
      expect(field).not.toMatch(/[+/=]/);
    }
  });

  it('privateKeyIv decodes to exactly 12 bytes', async () => {
    const { decodeBase64Url } = useCrypto();
    const { material } = await prepareRegistrationKeys(randomPassword());
    expect(decodeBase64Url(material.privateKeyIv)).toHaveLength(12);
  });

  it('privateKeySalt decodes to exactly 16 bytes', async () => {
    const { decodeBase64Url } = useCrypto();
    const { material } = await prepareRegistrationKeys(randomPassword());
    expect(decodeBase64Url(material.privateKeySalt)).toHaveLength(16);
  });

  it('returns a live KeyPair alongside the material', async () => {
    const { keyPair } = await prepareRegistrationKeys(randomPassword());
    expect(keyPair.publicKey.algorithm.name).toBe('X25519');
    expect(keyPair.privateKey.algorithm.name).toBe('X25519');
  });

  it('two calls produce different material (no key reuse)', async () => {
    const a = await prepareRegistrationKeys(randomPassword());
    const b = await prepareRegistrationKeys(randomPassword());
    expect(a.material.publicKey).not.toBe(b.material.publicKey);
    expect(a.material.encryptedPrivateKey).not.toBe(b.material.encryptedPrivateKey);
  });
});

describe('recoverKeyPair', () => {
  const { prepareRegistrationKeys, recoverKeyPair } = useCrypto();

  it('recovers the key pair with the correct password', async () => {
    const password = randomPassword();
    const { material } = await prepareRegistrationKeys(password);

    const recovered = await recoverKeyPair(
      password,
      material.encryptedPrivateKey,
      material.privateKeySalt,
      material.privateKeyIv,
      material.publicKey,
    );

    expect(recovered.privateKey.algorithm.name).toBe('X25519');
    expect(recovered.publicKey.algorithm.name).toBe('X25519');
  });

  it('recovered private key is not extractable', async () => {
    const password = randomPassword();
    const { material } = await prepareRegistrationKeys(password);

    const { privateKey } = await recoverKeyPair(
      password,
      material.encryptedPrivateKey,
      material.privateKeySalt,
      material.privateKeyIv,
      material.publicKey,
    );

    expect(privateKey.extractable).toBe(false);
  });

  it('rejects with the wrong password', async () => {
    const { material } = await prepareRegistrationKeys(randomPassword());

    await expect(
      recoverKeyPair(
        randomPassword(), // different password → wrong wrapping key
        material.encryptedPrivateKey,
        material.privateKeySalt,
        material.privateKeyIv,
        material.publicKey,
      ),
    ).rejects.toThrow();
  });

  it('recovered key pair can derive a shared secret with itself (ECDH sanity check)', async () => {
    const password = randomPassword();
    const { material } = await prepareRegistrationKeys(password);

    const { privateKey, publicKey } = await recoverKeyPair(
      password,
      material.encryptedPrivateKey,
      material.privateKeySalt,
      material.privateKeyIv,
      material.publicKey,
    );

    // A key pair should be able to derive bits against its own public key.
    await expect(
      crypto.subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256),
    ).resolves.not.toThrow();
  });
});
