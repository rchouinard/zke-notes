/**
 * keyStore — in-memory store for live CryptoKey objects.
 *
 * This store holds the user's unwrapped X25519 key pair for the duration of
 * the browser session. It is intentionally non-persistent: keys are never
 * written to localStorage, sessionStorage, or any serialised Pinia state.
 * The store is cleared explicitly on logout and implicitly on page refresh,
 * requiring the user to re-authenticate to unlock their private key.
 *
 * Security invariants:
 *  - Private keys held here are non-extractable CryptoKey objects.
 *  - No key material is ever serialised into JSON or put into storage.
 *  - `clearKeys()` must be called before any logout or session termination.
 */

import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import type { KeyPair } from '../composables/useCrypto';

export const useKeyStore = defineStore('key', () => {
  const privateKey = ref<CryptoKey | null>(null);
  const publicKey = ref<CryptoKey | null>(null);

  const hasKeys = computed(() => privateKey.value !== null && publicKey.value !== null);

  /**
   * Stores the user's key pair in memory.
   *
   * Called immediately after registration (keys freshly generated) or after a
   * successful login (keys recovered by `recoverKeyPair`). Once set, keys
   * remain available for all note crypto operations until `clearKeys` is called.
   *
   * @param pair - The `{ publicKey, privateKey }` pair to hold.
   */
  function setKeys(pair: KeyPair): void {
    privateKey.value = pair.privateKey;
    publicKey.value = pair.publicKey;
  }

  /**
   * Clears all key material from memory.
   *
   * Must be called on logout. Setting refs to `null` removes the last strong
   * references to the CryptoKey objects, allowing the GC to collect them.
   * The Web Crypto spec does not expose an explicit key-zeroisation API, so
   * this is the best available mechanism in a browser context.
   */
  function clearKeys(): void {
    privateKey.value = null;
    publicKey.value = null;
  }

  return {
    // State (exposed as readonly externally via storeToRefs)
    privateKey,
    publicKey,

    // Getters
    hasKeys,

    // Actions
    setKeys,
    clearKeys,
  };
});
