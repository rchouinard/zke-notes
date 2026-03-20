<?php

declare(strict_types=1);

namespace App\Crypto;

/**
 * Encrypts and decrypts note content for the CLI, mirroring what the SPA's
 * Web Crypto API does in the browser.  All operations use the same algorithms
 * and parameters as the client:
 *
 *   - Random AES-256-GCM content encryption key (CEK)
 *   - Note content encrypted/decrypted with the CEK (AES-256-GCM)
 *   - ECDH(userPrivate, userPublic) → HKDF-SHA-256 → AES-256-GCM CEK wrapping
 *   - PBKDF2-SHA-256 (600 000 iterations) to unwrap the user's private key
 *   - Base64url (no padding) encoding for every opaque blob stored on the server
 *
 * The server NEVER retains the CEK, the derived ECDH secret, or any plaintext.
 */
final class NoteCryptoGenerator implements NoteCryptoGeneratorInterface
{
    /** AES-GCM authentication-tag length in bytes. */
    private const TAG_BYTES = 16;

    /** AES-256-GCM IV length in bytes (96-bit nonce). */
    private const IV_BYTES = 12;

    /** PBKDF2 iteration count — must stay in sync with the SPA constant. */
    private const PBKDF2_ITERATIONS = 600_000;

    /** AES-256-GCM key length in bytes. */
    private const AES_KEY_BYTES = 32;

    /** X25519 key length in bytes. */
    private const X25519_KEY_BYTES = 32;

    /** HKDF-SHA-256 output length in bytes (256-bit derived key). */
    private const HKDF_KEY_BYTES = 32;

    /** HKDF info string — must stay in sync with the SPA constant. */
    private const HKDF_INFO = 'note-key-wrapping';

    /**
     * Encrypts note content and wraps the CEK using the user's key material.
     *
     * Steps performed (matching the SPA flow exactly):
     *   1. Unwrap the user's private key via PBKDF2 + AES-256-GCM.
     *   2. Generate a random AES-256-GCM CEK.
     *   3. Encrypt the note content with the CEK.
     *   4. Derive a wrapping key: ECDH(userPrivate, userPublic) → HKDF-SHA-256.
     *   5. Wrap the CEK with the derived wrapping key (AES-256-GCM).
     *   6. Return all opaque blobs as base64url-encoded strings.
     *
     * @param string $content             plaintext note content (title + body as a JSON string or raw text)
     * @param string $password            the user's plaintext password — used only to derive the private-key
     *                                    unwrapping key; not stored or logged
     * @param string $encryptedPrivateKey base64url-encoded AES-256-GCM ciphertext ‖ tag of the private key
     * @param string $privateKeySalt      base64url-encoded PBKDF2 salt
     * @param string $privateKeyIv        base64url-encoded AES-GCM IV used when the private key was wrapped
     * @param string $publicKey           base64url-encoded X25519 public key
     *
     * @return NoteKeyMaterial immutable value object with all blobs ready for persistence
     *
     * @throws \RuntimeException if any cryptographic operation fails
     */
    public function encrypt(
        string $content,
        string $password,
        string $encryptedPrivateKey,
        string $privateKeySalt,
        string $privateKeyIv,
        string $publicKey,
    ): NoteKeyMaterial {
        $secretKey = $this->unwrapPrivateKey(
            password: $password,
            encryptedPrivateKey: self::base64UrlDecode($encryptedPrivateKey),
            salt: self::base64UrlDecode($privateKeySalt),
            iv: self::base64UrlDecode($privateKeyIv),
        );

        $cek = random_bytes(self::AES_KEY_BYTES);

        $contentIvBytes = random_bytes(self::IV_BYTES);
        $encryptedContentBlob = $this->aesGcmEncrypt($content, $cek, $contentIvBytes);

        $publicKeyBytes = self::base64UrlDecode($publicKey);
        $wrappingKey = $this->deriveWrappingKey($secretKey, $publicKeyBytes);

        $contentKeyIvBytes = random_bytes(self::IV_BYTES);
        $encryptedCekBlob = $this->aesGcmEncrypt($cek, $wrappingKey, $contentKeyIvBytes);

        // Wipe sensitive material before returning.
        sodium_memzero($secretKey);
        sodium_memzero($cek);
        sodium_memzero($wrappingKey);

        return new NoteKeyMaterial(
            encryptedContent: self::base64UrlEncode($encryptedContentBlob),
            contentIv: self::base64UrlEncode($contentIvBytes),
            encryptedContentKey: self::base64UrlEncode($encryptedCekBlob),
            contentKeyIv: self::base64UrlEncode($contentKeyIvBytes),
        );
    }

    /**
     * Decrypts a note's content, performing the exact inverse of {@see encrypt}:
     *
     *   1. Unwrap the user's private key via PBKDF2 + AES-256-GCM.
     *   2. Derive the CEK-unwrapping key: ECDH(userPrivate, userPublic) → HKDF-SHA-256.
     *   3. Unwrap the CEK with the derived key (AES-256-GCM).
     *   4. Decrypt the note content with the CEK (AES-256-GCM).
     *
     * @throws \RuntimeException if any cryptographic step fails
     */
    public function decrypt(
        string $encryptedContent,
        string $contentIv,
        string $encryptedContentKey,
        string $contentKeyIv,
        string $password,
        string $encryptedPrivateKey,
        string $privateKeySalt,
        string $privateKeyIv,
        string $publicKey,
    ): string {
        $secretKey = $this->unwrapPrivateKey(
            password: $password,
            encryptedPrivateKey: self::base64UrlDecode($encryptedPrivateKey),
            salt: self::base64UrlDecode($privateKeySalt),
            iv: self::base64UrlDecode($privateKeyIv),
        );

        $publicKeyBytes = self::base64UrlDecode($publicKey);
        $wrappingKey = $this->deriveWrappingKey($secretKey, $publicKeyBytes);
        sodium_memzero($secretKey);

        $cek = $this->aesGcmDecrypt(
            blob: self::base64UrlDecode($encryptedContentKey),
            key: $wrappingKey,
            iv: self::base64UrlDecode($contentKeyIv),
            context: 'content encryption key',
        );
        sodium_memzero($wrappingKey);

        $plaintext = $this->aesGcmDecrypt(
            blob: self::base64UrlDecode($encryptedContent),
            key: $cek,
            iv: self::base64UrlDecode($contentIv),
            context: 'note content',
        );
        sodium_memzero($cek);

        return $plaintext;
    }

    /**
     * Derives the PBKDF2 wrapping key from the password + salt and decrypts
     * the stored private key blob (ciphertext ‖ GCM-tag).
     *
     * @throws \RuntimeException if decryption fails (wrong password or corrupted blob)
     */
    private function unwrapPrivateKey(
        string $password,
        string $encryptedPrivateKey,
        string $salt,
        string $iv,
    ): string {
        $wrappingKey = hash_pbkdf2(
            algo: 'sha256',
            password: $password,
            salt: $salt,
            iterations: self::PBKDF2_ITERATIONS,
            length: self::AES_KEY_BYTES,
            binary: true,
        );

        $ciphertext = substr($encryptedPrivateKey, 0, -self::TAG_BYTES);
        $tag = substr($encryptedPrivateKey, -self::TAG_BYTES);

        $secretKey = openssl_decrypt(
            data: $ciphertext,
            cipher_algo: 'aes-256-gcm',
            passphrase: $wrappingKey,
            options: OPENSSL_RAW_DATA,
            iv: $iv,
            tag: $tag,
        );

        sodium_memzero($wrappingKey);

        if (false === $secretKey || self::X25519_KEY_BYTES !== strlen($secretKey)) {
            throw new \RuntimeException('Failed to unwrap private key — incorrect password or corrupted key material.');
        }

        return $secretKey;
    }

    /**
     * Performs X25519 ECDH and runs the shared secret through HKDF-SHA-256 to
     * produce the AES-256-GCM CEK-wrapping key, matching the SPA's Web Crypto
     * `deriveBits` + `importKey` + `deriveKey` pipeline.
     *
     * @throws \RuntimeException if ECDH or HKDF fails
     */
    private function deriveWrappingKey(string $secretKey, string $publicKeyBytes): string
    {
        try {
            $sharedSecret = sodium_crypto_scalarmult($secretKey, $publicKeyBytes);
        } catch (\SodiumException $e) {
            throw new \RuntimeException(sprintf('ECDH key agreement failed: %s', $e->getMessage()), previous: $e);
        }

        /** @var string $derived */
        $derived = hash_hkdf('sha256', $sharedSecret, self::HKDF_KEY_BYTES, self::HKDF_INFO);
        sodium_memzero($sharedSecret);

        return $derived;
    }

    /**
     * Decrypts a ciphertext ‖ tag blob with AES-256-GCM.
     *
     * @param string $blob    raw binary ciphertext ‖ 16-byte GCM tag
     * @param string $key     raw 32-byte AES-256 key
     * @param string $iv      raw 12-byte GCM nonce
     * @param string $context human-readable label used in the exception message
     *
     * @throws \RuntimeException if decryption or authentication fails
     */
    private function aesGcmDecrypt(string $blob, string $key, string $iv, string $context): string
    {
        $ciphertext = substr($blob, 0, -self::TAG_BYTES);
        $tag = substr($blob, -self::TAG_BYTES);

        $plaintext = openssl_decrypt(
            data: $ciphertext,
            cipher_algo: 'aes-256-gcm',
            passphrase: $key,
            options: OPENSSL_RAW_DATA,
            iv: $iv,
            tag: $tag,
        );

        if (false === $plaintext) {
            throw new \RuntimeException(sprintf('AES-256-GCM decryption failed for %s — wrong key or corrupted data.', $context));
        }

        return $plaintext;
    }

    /**
     * Encrypts $plaintext with AES-256-GCM using $key and $iv.
     * Returns ciphertext ‖ tag as a single binary blob (matching Web Crypto behaviour).
     *
     * @throws \RuntimeException if OpenSSL encryption fails
     */
    private function aesGcmEncrypt(string $plaintext, string $key, string $iv): string
    {
        $tag = '';
        $ciphertext = openssl_encrypt(
            data: $plaintext,
            cipher_algo: 'aes-256-gcm',
            passphrase: $key,
            options: OPENSSL_RAW_DATA,
            iv: $iv,
            tag: $tag,
            aad: '',
            tag_length: self::TAG_BYTES,
        );

        if (false === $ciphertext) {
            throw new \RuntimeException('AES-256-GCM encryption failed.');
        }

        return $ciphertext.$tag;
    }

    /**
     * Encodes raw bytes as base64url without padding, matching the SPA's
     * `btoa` / `TextEncoder` pipeline.
     */
    private static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Decodes a base64url (no-padding) string to raw bytes.
     *
     * @throws \InvalidArgumentException if the input is not valid base64url
     */
    private static function base64UrlDecode(string $input): string
    {
        $padded = str_pad(strtr($input, '-_', '+/'), (int) (ceil(strlen($input) / 4) * 4), '=');
        $decoded = base64_decode($padded, strict: true);

        if (false === $decoded) {
            throw new \InvalidArgumentException('Invalid base64url input.');
        }

        return $decoded;
    }
}
