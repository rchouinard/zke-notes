<?php

declare(strict_types=1);

namespace App\Crypto;

/**
 * Immutable value object that carries the base64url-encoded cryptographic
 * material for a newly created user.
 *
 * All fields are opaque blobs from the server's perspective; their raw byte
 * content is only meaningful to the client (SPA) that holds the password.
 */
final readonly class UserKeyMaterial
{
    /**
     * @param string $publicKey           base64url-encoded X25519 public key (32 bytes raw)
     * @param string $encryptedPrivateKey base64url-encoded AES-256-GCM ciphertext || tag
     *                                    of the X25519 private key (48 bytes raw)
     * @param string $privateKeySalt      base64url-encoded PBKDF2 salt (16 bytes raw)
     * @param string $privateKeyIv        base64url-encoded AES-GCM IV (12 bytes raw)
     */
    public function __construct(
        public readonly string $publicKey,
        public readonly string $encryptedPrivateKey,
        public readonly string $privateKeySalt,
        public readonly string $privateKeyIv,
    ) {
    }
}
