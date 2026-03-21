/**
 * authStore — unit tests.
 *
 * Axios is mocked via vi.mock so no real HTTP calls are made. The useCrypto
 * composable is NOT mocked — real Web Crypto operations run against Node's
 * built-in implementation to keep the tests honest.
 *
 * Tests cover:
 *  - Initial state is empty / isAuthenticated false
 *  - register(): calls API in correct order, seeds key store, sets state
 *  - register(): propagates API errors
 *  - login(): fetches token, fetches user, unwraps keys, seeds key store
 *  - login(): rejects with wrong password (real crypto unwrap failure)
 *  - login(): propagates API errors
 *  - logout(): clears key store, resets all auth state
 *  - fetchCurrentUser(): refreshes user state from API
 *  - fetchCurrentUser(): throws when not authenticated
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { setActivePinia, createPinia } from 'pinia';
import { useAuthStore } from '../stores/authStore';
import { useKeyStore } from '../stores/keyStore';
import { useCrypto } from '../composables/useCrypto';

// ---------------------------------------------------------------------------
// Mock Axios
// ---------------------------------------------------------------------------

// We mock the entire boot/axios module so the stores get our fake `api`
// instance rather than the real one.
vi.mock('../boot/axios', () => {
  const post = vi.fn();
  const get = vi.fn();
  const interceptors = {
    request: { use: vi.fn() },
    response: { use: vi.fn() },
  };
  return {
    api: { post, get, interceptors },
  };
});

// Import the mocked api AFTER the mock declaration.
import { api } from '../boot/axios';

const mockPost = vi.spyOn(api, 'post');
const mockGet = vi.spyOn(api, 'get');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generates a random username for isolation between tests. */
function randomUsername(): string {
  return `user-${Math.random().toString(36).slice(2)}`;
}

/** Generates a random password for isolation between tests. */
function randomPassword(): string {
  return `pw-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

/**
 * Builds a realistic UserApiResponse by running the real client-side crypto,
 * so login tests can exercise the full unwrap path.
 */
async function buildUserApiResponse(username: string, password: string) {
  const { prepareRegistrationKeys } = useCrypto();
  const { material } = await prepareRegistrationKeys(password);
  return {
    id: '01JXXXXXXXXXXXXXXXXXXXXXXX',
    username,
    publicKey: material.publicKey,
    encryptedPrivateKey: material.encryptedPrivateKey,
    privateKeySalt: material.privateKeySalt,
    privateKeyIv: material.privateKeyIv,
  };
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  setActivePinia(createPinia());
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

describe('initial state', () => {
  it('userId is null', () => {
    expect(useAuthStore().userId).toBeNull();
  });

  it('username is null', () => {
    expect(useAuthStore().username).toBeNull();
  });

  it('token is null', () => {
    expect(useAuthStore().token).toBeNull();
  });

  it('isAuthenticated is false', () => {
    expect(useAuthStore().isAuthenticated).toBe(false);
  });

  it('encryptedPrivateKey is null', () => {
    expect(useAuthStore().encryptedPrivateKey).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// register()
// ---------------------------------------------------------------------------

describe('register()', () => {
  it('POSTs to /api/users then /api/auth', async () => {
    const username = randomUsername();
    const password = randomPassword();
    const userResponse = await buildUserApiResponse(username, password);

    mockPost
      .mockResolvedValueOnce({ data: userResponse }) // POST /api/users
      .mockResolvedValueOnce({ data: { token: 'tok-abc' } }); // POST /api/auth

    await useAuthStore().register(username, password);

    expect(mockPost).toHaveBeenCalledTimes(2);
    expect(mockPost.mock.calls[0]?.[0]).toBe('/api/users');
    expect(mockPost.mock.calls[1]?.[0]).toBe('/api/auth');
  });

  it('sends correct fields in the /api/users body', async () => {
    const username = randomUsername();
    const password = randomPassword();
    const userResponse = await buildUserApiResponse(username, password);

    mockPost
      .mockResolvedValueOnce({ data: userResponse })
      .mockResolvedValueOnce({ data: { token: 'tok-abc' } });

    await useAuthStore().register(username, password);

    const registrationBody = mockPost.mock.calls[0]?.[1] as Record<string, string>;
    expect(registrationBody).toHaveProperty('username', username);
    expect(registrationBody).toHaveProperty('password', password);
    expect(registrationBody).toHaveProperty('publicKey');
    expect(registrationBody).toHaveProperty('encryptedPrivateKey');
    expect(registrationBody).toHaveProperty('privateKeySalt');
    expect(registrationBody).toHaveProperty('privateKeyIv');
  });

  it('key material fields in the request body are non-empty base64url strings', async () => {
    const username = randomUsername();
    const password = randomPassword();
    const userResponse = await buildUserApiResponse(username, password);

    mockPost
      .mockResolvedValueOnce({ data: userResponse })
      .mockResolvedValueOnce({ data: { token: 'tok-abc' } });

    await useAuthStore().register(username, password);

    const body = mockPost.mock.calls[0]?.[1] as Record<string, string>;
    for (const field of ['publicKey', 'encryptedPrivateKey', 'privateKeySalt', 'privateKeyIv']) {
      const value = body[field];
      expect(typeof value).toBe('string');
      expect((value ?? '').length).toBeGreaterThan(0);
      expect(value).not.toMatch(/[+/=]/);
    }
  });

  it('sets userId, username, and token after success', async () => {
    const username = randomUsername();
    const password = randomPassword();
    const userResponse = await buildUserApiResponse(username, password);

    mockPost
      .mockResolvedValueOnce({ data: userResponse })
      .mockResolvedValueOnce({ data: { token: 'tok-abc' } });

    const store = useAuthStore();
    await store.register(username, password);

    expect(store.userId).toBe(userResponse.id);
    expect(store.username).toBe(username);
    expect(store.token).toBe('tok-abc');
    expect(store.isAuthenticated).toBe(true);
  });

  it('seeds the key store after success', async () => {
    const username = randomUsername();
    const password = randomPassword();
    const userResponse = await buildUserApiResponse(username, password);

    mockPost
      .mockResolvedValueOnce({ data: userResponse })
      .mockResolvedValueOnce({ data: { token: 'tok-abc' } });

    await useAuthStore().register(username, password);

    expect(useKeyStore().hasKeys).toBe(true);
    expect(useKeyStore().privateKey).not.toBeNull();
    expect(useKeyStore().publicKey).not.toBeNull();
  });

  it('propagates errors thrown by the API', async () => {
    mockPost.mockRejectedValueOnce(new Error('Network error'));
    await expect(useAuthStore().register(randomUsername(), randomPassword())).rejects.toThrow(
      'Network error',
    );
  });

  it('does not seed the key store when the API call fails', async () => {
    mockPost.mockRejectedValueOnce(new Error('500'));
    try {
      await useAuthStore().register(randomUsername(), randomPassword());
    } catch {
      // expected
    }
    expect(useKeyStore().hasKeys).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// login()
// ---------------------------------------------------------------------------

describe('login()', () => {
  it('POSTs to /api/auth then GETs /api/users/me', async () => {
    const username = randomUsername();
    const password = randomPassword();
    const userResponse = await buildUserApiResponse(username, password);

    mockPost.mockResolvedValueOnce({ data: { token: 'tok-xyz' } });
    mockGet.mockResolvedValueOnce({ data: userResponse });

    await useAuthStore().login(username, password);

    expect(mockPost).toHaveBeenCalledWith('/api/auth', { username, password });
    expect(mockGet).toHaveBeenCalledWith('/api/users/me');
  });

  it('sets token, userId, and username on success', async () => {
    const username = randomUsername();
    const password = randomPassword();
    const userResponse = await buildUserApiResponse(username, password);

    mockPost.mockResolvedValueOnce({ data: { token: 'tok-xyz' } });
    mockGet.mockResolvedValueOnce({ data: userResponse });

    const store = useAuthStore();
    await store.login(username, password);

    expect(store.token).toBe('tok-xyz');
    expect(store.userId).toBe(userResponse.id);
    expect(store.username).toBe(username);
    expect(store.isAuthenticated).toBe(true);
  });

  it('seeds the key store on success', async () => {
    const username = randomUsername();
    const password = randomPassword();
    const userResponse = await buildUserApiResponse(username, password);

    mockPost.mockResolvedValueOnce({ data: { token: 'tok-xyz' } });
    mockGet.mockResolvedValueOnce({ data: userResponse });

    await useAuthStore().login(username, password);

    expect(useKeyStore().hasKeys).toBe(true);
  });

  it('rejects when the password is wrong (crypto unwrap failure)', async () => {
    const username = randomUsername();
    const correctPassword = randomPassword();
    const wrongPassword = randomPassword();
    const userResponse = await buildUserApiResponse(username, correctPassword);

    mockPost.mockResolvedValueOnce({ data: { token: 'tok-xyz' } });
    mockGet.mockResolvedValueOnce({ data: userResponse });

    await expect(useAuthStore().login(username, wrongPassword)).rejects.toThrow();
  });

  it('does not seed the key store when the password is wrong', async () => {
    const username = randomUsername();
    const correctPassword = randomPassword();
    const wrongPassword = randomPassword();
    const userResponse = await buildUserApiResponse(username, correctPassword);

    mockPost.mockResolvedValueOnce({ data: { token: 'tok-xyz' } });
    mockGet.mockResolvedValueOnce({ data: userResponse });

    try {
      await useAuthStore().login(username, wrongPassword);
    } catch {
      // expected
    }

    expect(useKeyStore().hasKeys).toBe(false);
  });

  it('propagates errors from POST /api/auth', async () => {
    mockPost.mockRejectedValueOnce(new Error('Unauthorized'));
    await expect(useAuthStore().login(randomUsername(), randomPassword())).rejects.toThrow(
      'Unauthorized',
    );
  });

  it('propagates errors from GET /api/users/me', async () => {
    mockPost.mockResolvedValueOnce({ data: { token: 'tok-xyz' } });
    mockGet.mockRejectedValueOnce(new Error('Not Found'));
    await expect(useAuthStore().login(randomUsername(), randomPassword())).rejects.toThrow(
      'Not Found',
    );
  });
});

// ---------------------------------------------------------------------------
// logout()
// ---------------------------------------------------------------------------

describe('logout()', () => {
  /** Seeds the store with a mock session so logout has something to clear. */
  async function seedSession() {
    const username = randomUsername();
    const password = randomPassword();
    const userResponse = await buildUserApiResponse(username, password);

    mockPost
      .mockResolvedValueOnce({ data: userResponse })
      .mockResolvedValueOnce({ data: { token: 'tok-abc' } });

    await useAuthStore().register(username, password);
  }

  it('clears the key store', async () => {
    await seedSession();
    expect(useKeyStore().hasKeys).toBe(true);

    useAuthStore().logout();

    expect(useKeyStore().hasKeys).toBe(false);
    expect(useKeyStore().privateKey).toBeNull();
    expect(useKeyStore().publicKey).toBeNull();
  });

  it('resets all auth state', async () => {
    await seedSession();

    const store = useAuthStore();
    store.logout();

    expect(store.userId).toBeNull();
    expect(store.username).toBeNull();
    expect(store.token).toBeNull();
    expect(store.publicKey).toBeNull();
    expect(store.encryptedPrivateKey).toBeNull();
    expect(store.privateKeySalt).toBeNull();
    expect(store.privateKeyIv).toBeNull();
    expect(store.isAuthenticated).toBe(false);
  });

  it('is safe to call when not logged in', () => {
    expect(() => useAuthStore().logout()).not.toThrow();
  });

  it('clears keys before resetting state (order guarantee)', async () => {
    await seedSession();
    const keyStore = useKeyStore();
    const authStore = useAuthStore();

    const callOrder: string[] = [];
    const originalClear = keyStore.clearKeys.bind(keyStore);

    // Spy on clearKeys to record when it runs relative to token becoming null.
    vi.spyOn(keyStore, 'clearKeys').mockImplementation(() => {
      callOrder.push('clearKeys');
      callOrder.push(`token:${authStore.token ?? 'null'}`);
      originalClear();
    });

    authStore.logout();

    // clearKeys must be called while the token is still set (before state reset).
    expect(callOrder[0]).toBe('clearKeys');
    expect(callOrder[1]).not.toBe('token:null');
  });
});

// ---------------------------------------------------------------------------
// fetchCurrentUser()
// ---------------------------------------------------------------------------

describe('fetchCurrentUser()', () => {
  it('GETs /api/users/{id} and updates state', async () => {
    // Seed state directly to avoid a full register() flow.
    const store = useAuthStore();
    store.userId = '01JXXXXXXXXXXXXXXXXXX1111';
    store.token = 'tok-existing';

    const updatedUser = {
      id: '01JXXXXXXXXXXXXXXXXXX1111',
      username: 'refreshed-user',
      publicKey: 'pubkey-new',
      encryptedPrivateKey: 'enc-new',
      privateKeySalt: 'salt-new',
      privateKeyIv: 'iv-new',
    };
    mockGet.mockResolvedValueOnce({ data: updatedUser });

    await store.fetchCurrentUser();

    expect(mockGet).toHaveBeenCalledWith('/api/users/01JXXXXXXXXXXXXXXXXXX1111');
    expect(store.username).toBe('refreshed-user');
    expect(store.publicKey).toBe('pubkey-new');
    expect(store.encryptedPrivateKey).toBe('enc-new');
  });

  it('throws when not authenticated', async () => {
    await expect(useAuthStore().fetchCurrentUser()).rejects.toThrow(
      'Cannot fetch user: not authenticated.',
    );
  });

  it('propagates API errors', async () => {
    const store = useAuthStore();
    store.userId = '01JXXXXXXXXXXXXXXXXXX1111';
    store.token = 'tok-existing';

    mockGet.mockRejectedValueOnce(new Error('Server error'));

    await expect(store.fetchCurrentUser()).rejects.toThrow('Server error');
  });
});
