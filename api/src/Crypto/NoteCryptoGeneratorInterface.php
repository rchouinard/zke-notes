<?php

declare(strict_types=1);

namespace App\Crypto;

/**
 * Contract for encrypting and decrypting note content from the CLI,
 * mirroring what the SPA does in the browser.
 *
 * Extracting this interface keeps {@see \App\Command\NoteCreateCommand} and
 * {@see \App\Command\NoteFetchCommand} decoupled from the concrete
 * implementation, making them straightforward to unit-test with a mock or stub.
 */
interface NoteCryptoGeneratorInterface
{
    /**
     * Encrypts note content with a freshly generated AES-256-GCM content encryption
     * key (CEK), then wraps the CEK using a key derived from the user's X25519 key
     * pair via ECDH + HKDF-SHA-256.
     *
     * @param string $content             plaintext note content to encrypt
     * @param string $password            the user's plaintext password — only used to
     *                                    unwrap the stored private key; must never be
     *                                    stored or logged
     * @param string $encryptedPrivateKey base64url-encoded AES-256-GCM ciphertext ‖ tag
     *                                    of the user's X25519 private key
     * @param string $privateKeySalt      base64url-encoded PBKDF2 salt
     * @param string $privateKeyIv        base64url-encoded AES-GCM IV used when the
     *                                    private key was originally wrapped
     * @param string $publicKey           base64url-encoded X25519 public key
     *
     * @return NoteKeyMaterial immutable value object with all base64url-encoded
     *                         blobs ready for server-side persistence
     *
     * @throws \RuntimeException if any cryptographic step fails (e.g. wrong password,
     *                           corrupted key material, OpenSSL error)
     */
    public function encrypt(
        string $content,
        string $password,
        string $encryptedPrivateKey,
        string $privateKeySalt,
        string $privateKeyIv,
        string $publicKey,
    ): NoteKeyMaterial;

    /**
     * Decrypts a note's content, performing the exact inverse of {@see encrypt}:
     *
     *   1. Unwrap the user's private key via PBKDF2 + AES-256-GCM.
     *   2. Derive the CEK-unwrapping key: ECDH(userPrivate, userPublic) → HKDF-SHA-256.
     *   3. Unwrap the CEK with the derived key (AES-256-GCM).
     *   4. Decrypt the note content with the CEK (AES-256-GCM).
     *
     * @param string $encryptedContent    base64url-encoded AES-256-GCM ciphertext ‖ tag
     *                                    of the note content
     * @param string $contentIv           base64url-encoded 96-bit IV used to encrypt content
     * @param string $encryptedContentKey base64url-encoded AES-256-GCM ciphertext ‖ tag
     *                                    of the CEK
     * @param string $contentKeyIv        base64url-encoded 96-bit IV used to wrap the CEK
     * @param string $password            the user's plaintext password; must never be
     *                                    stored or logged
     * @param string $encryptedPrivateKey base64url-encoded wrapped X25519 private key blob
     * @param string $privateKeySalt      base64url-encoded PBKDF2 salt
     * @param string $privateKeyIv        base64url-encoded IV used when the private key
     *                                    was originally wrapped
     * @param string $publicKey           base64url-encoded X25519 public key
     *
     * @return string the decrypted plaintext content
     *
     * @throws \RuntimeException if any cryptographic step fails (e.g. wrong password,
     *                           corrupted key material, authentication tag mismatch)
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
    ): string;
}
