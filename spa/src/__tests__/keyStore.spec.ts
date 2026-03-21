/**
 * keyStore — unit tests.
 *
 * Tests cover:
 *  - Initial state is null / hasKeys false
 *  - setKeys populates both refs and flips hasKeys
 *  - clearKeys resets both refs and flips hasKeys back
 *  - Stored CryptoKey objects are the exact same references passed in
 *  - clearKeys is idempotent (safe to call when already clear)
 *  - CryptoKey values are not JSON-serialisable (ensuring they cannot
 *    accidentally end up in persisted storage as plain objects)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setActivePinia, createPinia } from 'pinia';
import { useKeyStore } from '../stores/keyStore';
import { useCrypto } from '../composables/useCrypto';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generates a fresh X25519 key pair for test use. */
async function makeKeyPair() {
  return useCrypto().generateKeyPair();
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  setActivePinia(createPinia());
});

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

describe('initial state', () => {
  it('privateKey is null', () => {
    const store = useKeyStore();
    expect(store.privateKey).toBeNull();
  });

  it('publicKey is null', () => {
    const store = useKeyStore();
    expect(store.publicKey).toBeNull();
  });

  it('hasKeys is false', () => {
    const store = useKeyStore();
    expect(store.hasKeys).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// setKeys
// ---------------------------------------------------------------------------

describe('setKeys', () => {
  it('populates privateKey and publicKey', async () => {
    const store = useKeyStore();
    const keyPair = await makeKeyPair();
    store.setKeys(keyPair);
    expect(store.privateKey).toBe(keyPair.privateKey);
    expect(store.publicKey).toBe(keyPair.publicKey);
  });

  it('sets hasKeys to true', async () => {
    const store = useKeyStore();
    store.setKeys(await makeKeyPair());
    expect(store.hasKeys).toBe(true);
  });

  it('stores the exact CryptoKey reference (no cloning)', async () => {
    const store = useKeyStore();
    const keyPair = await makeKeyPair();
    store.setKeys(keyPair);
    expect(store.privateKey).toBe(keyPair.privateKey);
    expect(store.publicKey).toBe(keyPair.publicKey);
  });

  it('overwrites previously set keys', async () => {
    const store = useKeyStore();
    const first = await makeKeyPair();
    const second = await makeKeyPair();
    store.setKeys(first);
    store.setKeys(second);
    expect(store.privateKey).toBe(second.privateKey);
    expect(store.publicKey).toBe(second.publicKey);
  });
});

// ---------------------------------------------------------------------------
// clearKeys
// ---------------------------------------------------------------------------

describe('clearKeys', () => {
  it('resets privateKey to null', async () => {
    const store = useKeyStore();
    store.setKeys(await makeKeyPair());
    store.clearKeys();
    expect(store.privateKey).toBeNull();
  });

  it('resets publicKey to null', async () => {
    const store = useKeyStore();
    store.setKeys(await makeKeyPair());
    store.clearKeys();
    expect(store.publicKey).toBeNull();
  });

  it('sets hasKeys to false', async () => {
    const store = useKeyStore();
    store.setKeys(await makeKeyPair());
    store.clearKeys();
    expect(store.hasKeys).toBe(false);
  });

  it('is idempotent when called on an already-clear store', () => {
    const store = useKeyStore();
    expect(() => store.clearKeys()).not.toThrow();
    expect(store.hasKeys).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Serialisation safety
// ---------------------------------------------------------------------------

describe('serialisation safety', () => {
  it('CryptoKey objects do not serialise to meaningful JSON', async () => {
    const store = useKeyStore();
    store.setKeys(await makeKeyPair());

    // JSON.stringify of a CryptoKey produces "{}" — not key bytes.
    // This verifies the key cannot accidentally leak into persisted storage
    // as a plain object.
    const serialised = JSON.stringify({
      privateKey: store.privateKey,
      publicKey: store.publicKey,
    });
    const parsed = JSON.parse(serialised) as { privateKey: unknown; publicKey: unknown };
    expect(parsed.privateKey).toEqual({});
    expect(parsed.publicKey).toEqual({});
  });
});
