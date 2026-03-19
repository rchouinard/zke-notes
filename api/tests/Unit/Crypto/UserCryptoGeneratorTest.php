<?php

declare(strict_types=1);

namespace App\Tests\Unit\Crypto;

use App\Crypto\UserCryptoGenerator;
use App\Crypto\UserKeyMaterial;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for {@see UserCryptoGenerator}.
 *
 * These tests verify the cryptographic contract without touching the database.
 * They use randomly generated passwords per invocation so no hardcoded secrets
 * are present in the test suite.
 */
final class UserCryptoGeneratorTest extends TestCase
{
    private UserCryptoGenerator $generator;

    protected function setUp(): void
    {
        $this->generator = new UserCryptoGenerator();
    }

    public function testGenerateReturnsUserKeyMaterial(): void
    {
        $result = $this->generator->generate($this->randomPassword());

        self::assertInstanceOf(UserKeyMaterial::class, $result);
    }

    public function testAllFieldsAreValidBase64Url(): void
    {
        $material = $this->generator->generate($this->randomPassword());

        $base64UrlPattern = '/^[A-Za-z0-9_\-]+$/';

        self::assertMatchesRegularExpression($base64UrlPattern, $material->publicKey, 'publicKey must be base64url');
        self::assertMatchesRegularExpression($base64UrlPattern, $material->encryptedPrivateKey, 'encryptedPrivateKey must be base64url');
        self::assertMatchesRegularExpression($base64UrlPattern, $material->privateKeySalt, 'privateKeySalt must be base64url');
        self::assertMatchesRegularExpression($base64UrlPattern, $material->privateKeyIv, 'privateKeyIv must be base64url');
    }

    public function testNoBase64PaddingCharacters(): void
    {
        $material = $this->generator->generate($this->randomPassword());

        self::assertStringNotContainsString('=', $material->publicKey);
        self::assertStringNotContainsString('=', $material->encryptedPrivateKey);
        self::assertStringNotContainsString('=', $material->privateKeySalt);
        self::assertStringNotContainsString('=', $material->privateKeyIv);
    }

    /**
     * X25519 public key is 32 raw bytes → 43 base64url chars (no padding).
     */
    public function testPublicKeyIsX25519Length(): void
    {
        $material = $this->generator->generate($this->randomPassword());
        $rawBytes = $this->base64UrlDecode($material->publicKey);

        self::assertSame(32, strlen($rawBytes), 'X25519 public key must be 32 bytes');
    }

    /**
     * Encrypted private key = 32-byte ciphertext ‖ 16-byte AES-GCM tag → 48 bytes raw.
     */
    public function testEncryptedPrivateKeyLength(): void
    {
        $material = $this->generator->generate($this->randomPassword());
        $rawBytes = $this->base64UrlDecode($material->encryptedPrivateKey);

        self::assertSame(48, strlen($rawBytes), 'Encrypted private key blob must be 48 bytes (32 ct + 16 tag)');
    }

    /**
     * PBKDF2 salt is 16 raw bytes.
     */
    public function testPrivateKeySaltLength(): void
    {
        $material = $this->generator->generate($this->randomPassword());
        $rawBytes = $this->base64UrlDecode($material->privateKeySalt);

        self::assertSame(16, strlen($rawBytes), 'Salt must be 16 bytes');
    }

    /**
     * AES-GCM IV is 12 raw bytes (96-bit nonce).
     */
    public function testPrivateKeyIvLength(): void
    {
        $material = $this->generator->generate($this->randomPassword());
        $rawBytes = $this->base64UrlDecode($material->privateKeyIv);

        self::assertSame(12, strlen($rawBytes), 'IV must be 12 bytes');
    }

    /**
     * Each call must produce a distinct key pair.
     */
    public function testEachCallProducesUniquePublicKey(): void
    {
        $password = $this->randomPassword();

        $keys = array_map(
            fn () => $this->generator->generate($password)->publicKey,
            range(1, 20),
        );

        self::assertSame(count($keys), count(array_unique($keys)), 'All generated public keys must be unique');
    }

    /**
     * Each call must produce a unique salt (otherwise PBKDF2 is deterministic
     * for the same password across registrations).
     */
    public function testEachCallProducesUniqueSalt(): void
    {
        $password = $this->randomPassword();

        $salts = array_map(
            fn () => $this->generator->generate($password)->privateKeySalt,
            range(1, 20),
        );

        self::assertSame(count($salts), count(array_unique($salts)), 'All salts must be unique');
    }

    /**
     * Each call must produce a unique IV — reusing an IV with the same key
     * would be catastrophic for AES-GCM.
     */
    public function testEachCallProducesUniqueIv(): void
    {
        $password = $this->randomPassword();

        $ivs = array_map(
            fn () => $this->generator->generate($password)->privateKeyIv,
            range(1, 20),
        );

        self::assertSame(count($ivs), count(array_unique($ivs)), 'All IVs must be unique');
    }

    /**
     * The encrypted private key must be decryptable with the correct password,
     * and must correspond to the paired public key.
     */
    public function testEncryptedPrivateKeyDecryptsToMatchingPublicKey(): void
    {
        $password = $this->randomPassword();
        $material = $this->generator->generate($password);

        $encryptedBlob = $this->base64UrlDecode($material->encryptedPrivateKey);
        $salt = $this->base64UrlDecode($material->privateKeySalt);
        $iv = $this->base64UrlDecode($material->privateKeyIv);
        $publicKey = $this->base64UrlDecode($material->publicKey);

        // Re-derive the wrapping key the same way the generator does.
        $wrappingKey = hash_pbkdf2('sha256', $password, $salt, 600_000, 32, true);

        $ciphertext = substr($encryptedBlob, 0, -16);
        $tag = substr($encryptedBlob, -16);

        $secretKey = openssl_decrypt(
            data: $ciphertext,
            cipher_algo: 'aes-256-gcm',
            passphrase: $wrappingKey,
            options: OPENSSL_RAW_DATA,
            iv: $iv,
            tag: $tag,
        );

        self::assertNotFalse($secretKey, 'Decryption must succeed with the correct password');
        self::assertSame(32, strlen($secretKey), 'X25519 private key must be 32 bytes');

        // Derive the corresponding public key from the private key and compare.
        $derivedPublicKey = sodium_crypto_scalarmult_base($secretKey);
        self::assertSame($publicKey, $derivedPublicKey, 'Derived public key must match stored public key');
    }

    /**
     * Decryption with a wrong password must fail (authentication tag mismatch).
     */
    public function testDecryptionFailsWithWrongPassword(): void
    {
        $material = $this->generator->generate($this->randomPassword());

        $encryptedBlob = $this->base64UrlDecode($material->encryptedPrivateKey);
        $salt = $this->base64UrlDecode($material->privateKeySalt);
        $iv = $this->base64UrlDecode($material->privateKeyIv);

        $wrongWrappingKey = hash_pbkdf2('sha256', $this->randomPassword(), $salt, 600_000, 32, true);

        $ciphertext = substr($encryptedBlob, 0, -16);
        $tag = substr($encryptedBlob, -16);

        $result = openssl_decrypt(
            data: $ciphertext,
            cipher_algo: 'aes-256-gcm',
            passphrase: $wrongWrappingKey,
            options: OPENSSL_RAW_DATA,
            iv: $iv,
            tag: $tag,
        );

        self::assertFalse($result, 'Decryption with wrong password must return false (tag mismatch)');
    }

    /**
     * Generates a cryptographically random password for each test — no
     * hardcoded secrets in the test suite.
     */
    private function randomPassword(): string
    {
        return base64_encode(random_bytes(24));
    }

    /**
     * Decodes a base64url (no-padding) string to raw bytes.
     */
    private function base64UrlDecode(string $input): string
    {
        $padded = str_pad(strtr($input, '-_', '+/'), (int) (ceil(strlen($input) / 4) * 4), '=');

        return (string) base64_decode($padded, strict: true);
    }
}
