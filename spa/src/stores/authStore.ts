/**
 * authStore — authentication state and session lifecycle.
 *
 * Responsibilities:
 *  - `register()`: run client-side crypto, POST to /api/users, then seed the
 *    key store so the user is immediately active without a second login.
 *  - `login()`: authenticate with the API, fetch the user's encrypted key
 *    material, derive the wrapping key from the password, unwrap the private
 *    key, and seed the key store.
 *  - `logout()`: clear the key store and all session state.
 *  - `fetchCurrentUser()`: refresh the persisted user record from the API.
 *
 * Persistence: `userId`, `username`, and the encrypted key blobs are written
 * to `sessionStorage` so that a hard-refresh can re-prompt for the password
 * rather than forcing a full logout. The JWT token is also stored there.
 * Nothing in `localStorage` is ever written.
 *
 * Security invariants:
 *  - Plaintext passwords are never stored anywhere.
 *  - Raw private key bytes are never stored anywhere.
 *  - The `keyStore` is always cleared before any state reset.
 */

import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { api } from '../boot/axios';
import { useCrypto } from '../composables/useCrypto';
import { useKeyStore } from './keyStore';

interface UserApiResponse {
  id: string;
  username: string;
  publicKey: string;
  encryptedPrivateKey: string;
  privateKeySalt: string;
  privateKeyIv: string;
}

interface AuthTokenResponse {
  token: string;
}

export const useAuthStore = defineStore(
  'auth',
  () => {
    const userId = ref<string | null>(null);
    const username = ref<string | null>(null);
    const token = ref<string | null>(null);
    const publicKey = ref<string | null>(null);
    const encryptedPrivateKey = ref<string | null>(null);
    const privateKeySalt = ref<string | null>(null);
    const privateKeyIv = ref<string | null>(null);

    const isAuthenticated = computed(() => token.value !== null);

    function applyUserResponse(user: UserApiResponse): void {
      userId.value = user.id;
      username.value = user.username;
      publicKey.value = user.publicKey;
      encryptedPrivateKey.value = user.encryptedPrivateKey;
      privateKeySalt.value = user.privateKeySalt;
      privateKeyIv.value = user.privateKeyIv;
    }

    function resetState(): void {
      userId.value = null;
      username.value = null;
      token.value = null;
      publicKey.value = null;
      encryptedPrivateKey.value = null;
      privateKeySalt.value = null;
      privateKeyIv.value = null;
    }

    /**
     * Registers a new user.
     *
     * Sequence:
     *  1. Generate an X25519 key pair and wrap the private key with a
     *     PBKDF2-derived AES-256-GCM key (all client-side via `useCrypto`).
     *  2. POST the username, password, and all opaque key blobs to /api/users.
     *  3. Immediately log in: POST /api/auth for a JWT token.
     *  4. Seed the key store with the freshly generated key pair.
     *
     * @param username - The desired username.
     * @param password - The user's chosen password (used only within this call).
     *
     * @throws {Error} if crypto fails, or if the API returns an error.
     */
    async function register(username: string, password: string): Promise<void> {
      const crypto = useCrypto();

      const { material, keyPair } = await crypto.prepareRegistrationKeys(password);

      const { data: user } = await api.post<UserApiResponse>('/api/users', {
        username,
        password,
        publicKey: material.publicKey,
        encryptedPrivateKey: material.encryptedPrivateKey,
        privateKeySalt: material.privateKeySalt,
        privateKeyIv: material.privateKeyIv,
      });

      applyUserResponse(user);

      const { data: auth } = await api.post<AuthTokenResponse>('/api/auth', {
        username,
        password,
      });

      token.value = auth.token;

      useKeyStore().setKeys(keyPair);
    }

    /**
     * Logs in an existing user.
     *
     * Sequence:
     *  1. POST /api/auth to obtain a JWT token.
     *  2. GET /api/users/{id} to fetch the encrypted key material.
     *  3. Derive the PBKDF2 wrapping key from the password and stored salt.
     *  4. Unwrap the private key (wrong password → AES-GCM tag failure → throws).
     *  5. Seed the key store with the recovered key pair.
     *
     * @param username - The user's username.
     * @param password - The user's password (used only within this call to unwrap
     *                   the private key; never stored).
     *
     * @throws {Error} if authentication fails, the API is unreachable, or the
     *                 password is incorrect (private key unwrapping failure).
     */
    async function login(username: string, password: string): Promise<void> {
      const { data: auth } = await api.post<AuthTokenResponse>('/api/auth', {
        username,
        password,
      });

      token.value = auth.token;
      const { data: user } = await api.get<UserApiResponse>(`/api/users/me`);
      applyUserResponse(user);

      const keyPair = await useCrypto().recoverKeyPair(
        password,
        user.encryptedPrivateKey,
        user.privateKeySalt,
        user.privateKeyIv,
        user.publicKey,
      );

      useKeyStore().setKeys(keyPair);
    }

    /**
     * Logs out the current user.
     *
     * Clears the key store first to ensure no key material lingers in memory,
     * then resets all auth state. Callers should navigate to /login afterwards.
     */
    function logout(): void {
      useKeyStore().clearKeys();
      resetState();
    }

    /**
     * Re-fetches the current user's profile from the API and updates state.
     *
     * Useful for refreshing encrypted key blobs after a password change or to
     * ensure the local state reflects the server. Requires an active session.
     *
     * @throws {Error} if not authenticated or the API call fails.
     */
    async function fetchCurrentUser(): Promise<void> {
      if (!userId.value) {
        throw new Error('Cannot fetch user: not authenticated.');
      }

      const { data: user } = await api.get<UserApiResponse>(`/api/users/${userId.value}`);
      applyUserResponse(user);
    }

    return {
      // State
      userId,
      username,
      token,
      publicKey,
      encryptedPrivateKey,
      privateKeySalt,
      privateKeyIv,

      // Getters
      isAuthenticated,

      // Actions
      register,
      login,
      logout,
      fetchCurrentUser,
    };
  },
  {
    // Persist all state to sessionStorage so a hard-refresh re-prompts for
    // the password rather than forcing a full logout. The token will be
    // invalid after a server restart anyway, so security exposure is minimal.
    ...(typeof window !== 'undefined' ? { persist: { storage: window.sessionStorage } } : {}),
  },
);
