<?php

declare(strict_types=1);

namespace App\Crypto;

/**
 * Generates all server-side cryptographic material required to register a new user.
 *
 * This service mirrors what the SPA's Web Crypto API does during registration so
 * that the CLI can bootstrap users without a browser session.  All operations use
 * the same algorithms and parameters as the client:
 *
 *   - X25519 key pair via libsodium (sodium_crypto_box_keypair)
 *   - PBKDF2-SHA-256 (600 000 iterations) for the password-derived wrapping key
 *   - AES-256-GCM for encrypting the private key (ciphertext ‖ tag blob)
 *   - Base64url (no padding) encoding for every opaque blob stored on the server
 *
 * The server NEVER persists the raw private key or the plaintext password; only
 * the encrypted blob, the public key, the salt, and the IV are stored.
 */
final class UserCryptoGenerator implements UserCryptoGeneratorInterface
{
    // AES-GCM authentication-tag length in bytes.
    private const TAG_BYTES = 16;

    // AES-256-GCM IV length in bytes (96-bit nonce).
    private const IV_BYTES = 12;

    // PBKDF2 salt length in bytes.
    private const SALT_BYTES = 16;

    // PBKDF2 iteration count — must stay in sync with the SPA constant.
    private const PBKDF2_ITERATIONS = 600_000;

    // AES-256-GCM wrapping key length in bytes.
    private const WRAPPING_KEY_BYTES = 32;

    /**
     * Generates a fresh X25519 key pair and wraps the private key with a key
     * derived from the given password via PBKDF2-SHA-256 -> AES-256-GCM.
     *
     * @param string $password the user's plaintext password (only held in memory
     *                         long enough to derive the wrapping key, then gone)
     *
     * @return UserKeyMaterial value object carrying all base64url-encoded fields
     *                         ready to be persisted by the caller
     *
     * @throws \SodiumException  if libsodium key generation fails
     * @throws \RuntimeException if OpenSSL encryption fails
     */
    public function generate(string $password): UserKeyMaterial
    {
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $secretKey = sodium_crypto_box_secretkey($keyPair);

        $salt = random_bytes(self::SALT_BYTES);
        $iv = random_bytes(self::IV_BYTES);

        $wrappingKey = hash_pbkdf2(
            algo: 'sha256',
            password: $password,
            salt: $salt,
            iterations: self::PBKDF2_ITERATIONS,
            length: self::WRAPPING_KEY_BYTES,
            binary: true,
        );

        $tag = '';
        $encryptedKeyBody = openssl_encrypt(
            data: $secretKey,
            cipher_algo: 'aes-256-gcm',
            passphrase: $wrappingKey,
            options: OPENSSL_RAW_DATA,
            iv: $iv,
            tag: $tag,
            aad: '',
            tag_length: self::TAG_BYTES,
        );

        if (false === $encryptedKeyBody) {
            throw new \RuntimeException('AES-256-GCM encryption of private key failed.');
        }

        // Store ciphertext || tag as a single blob, matching Web Crypto behaviour
        // (SubtleCrypto.encrypt with AES-GCM appends the tag to the ciphertext).
        $encryptedPrivateKey = $encryptedKeyBody.$tag;

        // Wipe sensitive material from memory before returning.
        sodium_memzero($secretKey);
        sodium_memzero($wrappingKey);

        return new UserKeyMaterial(
            publicKey: self::base64UrlEncode($publicKey),
            encryptedPrivateKey: self::base64UrlEncode($encryptedPrivateKey),
            privateKeySalt: self::base64UrlEncode($salt),
            privateKeyIv: self::base64UrlEncode($iv),
        );
    }

    private static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
