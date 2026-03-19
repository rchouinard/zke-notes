<?php

declare(strict_types=1);

namespace App\Crypto;

/**
 * Contract for generating the cryptographic material required to register a new user.
 *
 * Extracting this interface lets the {@see \App\Command\UserCreateCommand} and any
 * other consumer remain decoupled from the concrete implementation, making them
 * straightforward to unit-test with a mock or stub.
 */
interface UserCryptoGeneratorInterface
{
    /**
     * Generates a fresh X25519 key pair and wraps the private key with an
     * AES-256-GCM key derived from the given password via PBKDF2-SHA-256.
     *
     * @param string $password The user's plaintext password.  Must not be
     *                         stored or logged by any implementation.
     *
     * @return UserKeyMaterial immutable value object with all base64url-encoded
     *                         fields ready for server-side storage
     *
     * @throws \RuntimeException if key generation or encryption fails
     */
    public function generate(string $password): UserKeyMaterial;
}
