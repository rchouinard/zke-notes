<?php

declare(strict_types=1);

namespace App\Tests\Unit\Crypto;

use App\Crypto\NoteCryptoGenerator;
use App\Crypto\NoteKeyMaterial;
use App\Crypto\UserCryptoGenerator;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for {@see NoteCryptoGenerator}.
 *
 * Tests verify the full cryptographic contract without touching the database.
 * A real {@see UserCryptoGenerator} is used to produce valid key material so
 * the round-trip tests are end-to-end without any mocks on the crypto path.
 * No hardcoded passwords, keys, or secrets appear — all sensitive values are
 * randomly generated per test run.
 */
final class NoteCryptoGeneratorTest extends TestCase
{
    private NoteCryptoGenerator $noteGenerator;
    private UserCryptoGenerator $userGenerator;

    protected function setUp(): void
    {
        $this->noteGenerator = new NoteCryptoGenerator();
        $this->userGenerator = new UserCryptoGenerator();
    }

    // ── Return type ──────────────────────────────────────────────────────────

    public function testEncryptReturnsNoteKeyMaterial(): void
    {
        [$password, $userMaterial] = $this->makeUser();

        $result = $this->noteGenerator->encrypt(
            content: 'Hello, world!',
            password: $password,
            encryptedPrivateKey: $userMaterial->encryptedPrivateKey,
            privateKeySalt: $userMaterial->privateKeySalt,
            privateKeyIv: $userMaterial->privateKeyIv,
            publicKey: $userMaterial->publicKey,
        );

        self::assertInstanceOf(NoteKeyMaterial::class, $result);
    }

    // ── Base64url format ─────────────────────────────────────────────────────

    public function testAllFieldsAreValidBase64Url(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $material = $this->encryptNote('Some content', $password, $userMaterial);

        $base64UrlPattern = '/^[A-Za-z0-9_\-]+$/';

        self::assertMatchesRegularExpression($base64UrlPattern, $material->encryptedContent, 'encryptedContent must be base64url');
        self::assertMatchesRegularExpression($base64UrlPattern, $material->contentIv, 'contentIv must be base64url');
        self::assertMatchesRegularExpression($base64UrlPattern, $material->encryptedContentKey, 'encryptedContentKey must be base64url');
        self::assertMatchesRegularExpression($base64UrlPattern, $material->contentKeyIv, 'contentKeyIv must be base64url');
    }

    public function testNoBase64PaddingCharacters(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $material = $this->encryptNote('Padding test', $password, $userMaterial);

        self::assertStringNotContainsString('=', $material->encryptedContent);
        self::assertStringNotContainsString('=', $material->contentIv);
        self::assertStringNotContainsString('=', $material->encryptedContentKey);
        self::assertStringNotContainsString('=', $material->contentKeyIv);
    }

    // ── IV lengths (96-bit / 12 bytes raw → 16 base64url chars) ─────────────

    public function testContentIvIsCorrectLength(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $material = $this->encryptNote('IV length check', $password, $userMaterial);

        self::assertSame(12, strlen($this->base64UrlDecode($material->contentIv)), 'Content IV must be 12 bytes');
    }

    public function testContentKeyIvIsCorrectLength(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $material = $this->encryptNote('Key IV length check', $password, $userMaterial);

        self::assertSame(12, strlen($this->base64UrlDecode($material->contentKeyIv)), 'Content-key IV must be 12 bytes');
    }

    // ── IV uniqueness ─────────────────────────────────────────────────────────

    /**
     * Each encryption must produce a unique content IV (statistical test).
     */
    public function testContentIvsAreUniqueAcrossEncryptions(): void
    {
        [$password, $userMaterial] = $this->makeUser();

        $ivs = array_map(
            fn () => $this->encryptNote($this->randomContent(), $password, $userMaterial)->contentIv,
            range(1, 100),
        );

        self::assertSame(100, count(array_unique($ivs)), 'All content IVs across 100 encryptions must be unique');
    }

    /**
     * Each encryption must produce a unique content-key IV.
     */
    public function testContentKeyIvsAreUniqueAcrossEncryptions(): void
    {
        [$password, $userMaterial] = $this->makeUser();

        $ivs = array_map(
            fn () => $this->encryptNote($this->randomContent(), $password, $userMaterial)->contentKeyIv,
            range(1, 100),
        );

        self::assertSame(100, count(array_unique($ivs)), 'All content-key IVs across 100 encryptions must be unique');
    }

    // ── Encrypted content length ─────────────────────────────────────────────

    /**
     * Encrypted content blob = plaintext bytes + 16-byte GCM tag.
     */
    public function testEncryptedContentLengthMatchesPlaintextPlusTag(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $plaintext = 'Exactly this string.';

        $material = $this->encryptNote($plaintext, $password, $userMaterial);

        $expectedBytes = strlen($plaintext) + 16; // 16-byte GCM auth tag
        self::assertSame(
            $expectedBytes,
            strlen($this->base64UrlDecode($material->encryptedContent)),
            'Encrypted content must be plaintext length + 16 (GCM tag)',
        );
    }

    /**
     * Encrypted CEK blob = 32-byte CEK ciphertext + 16-byte GCM tag → 48 bytes raw.
     */
    public function testEncryptedContentKeyLength(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $material = $this->encryptNote('CEK length test', $password, $userMaterial);

        self::assertSame(
            48,
            strlen($this->base64UrlDecode($material->encryptedContentKey)),
            'Encrypted CEK must be 48 bytes (32 ciphertext + 16 GCM tag)',
        );
    }

    // ── Decrypt round-trip ────────────────────────────────────────────────────

    public function testDecryptRoundTripRecoverOriginalContent(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $original = 'The quick brown fox jumps over the lazy dog.';

        $material = $this->encryptNote($original, $password, $userMaterial);
        $decrypted = $this->decryptNote($material, $password, $userMaterial);

        self::assertSame($original, $decrypted);
    }

    public function testDecryptRoundTripWithEmptyContent(): void
    {
        [$password, $userMaterial] = $this->makeUser();

        $material = $this->encryptNote('', $password, $userMaterial);
        $decrypted = $this->decryptNote($material, $password, $userMaterial);

        self::assertSame('', $decrypted);
    }

    public function testDecryptRoundTripWithMultibyteContent(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $original = '日本語テスト 🔑 café';

        $material = $this->encryptNote($original, $password, $userMaterial);
        $decrypted = $this->decryptNote($material, $password, $userMaterial);

        self::assertSame($original, $decrypted);
    }

    public function testDecryptOutputMatchesOriginalExactly(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $original = $this->randomContent();

        $material = $this->encryptNote($original, $password, $userMaterial);

        // Run multiple decrypt calls on the same ciphertext to confirm determinism.
        self::assertSame($original, $this->decryptNote($material, $password, $userMaterial));
        self::assertSame($original, $this->decryptNote($material, $password, $userMaterial));
    }

    // ── Wrong password (decrypt) ──────────────────────────────────────────────

    public function testDecryptWithWrongPasswordThrowsRuntimeException(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $material = $this->encryptNote('Secret', $password, $userMaterial);

        $this->expectException(\RuntimeException::class);

        $this->decryptNote($material, $this->randomPassword(), $userMaterial);
    }

    // ── Corrupted blobs (decrypt) ─────────────────────────────────────────────

    public function testDecryptWithCorruptedEncryptedContentThrowsRuntimeException(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $material = $this->encryptNote('Secret', $password, $userMaterial);

        $corrupted = new NoteKeyMaterial(
            encryptedContent: $this->flipFirstByte($material->encryptedContent),
            contentIv: $material->contentIv,
            encryptedContentKey: $material->encryptedContentKey,
            contentKeyIv: $material->contentKeyIv,
        );

        $this->expectException(\RuntimeException::class);

        $this->decryptNote($corrupted, $password, $userMaterial);
    }

    public function testDecryptWithCorruptedEncryptedContentKeyThrowsRuntimeException(): void
    {
        [$password, $userMaterial] = $this->makeUser();
        $material = $this->encryptNote('Secret', $password, $userMaterial);

        $corrupted = new NoteKeyMaterial(
            encryptedContent: $material->encryptedContent,
            contentIv: $material->contentIv,
            encryptedContentKey: $this->flipFirstByte($material->encryptedContentKey),
            contentKeyIv: $material->contentKeyIv,
        );

        $this->expectException(\RuntimeException::class);

        $this->decryptNote($corrupted, $password, $userMaterial);
    }

    // ── Wrong password (encrypt) ──────────────────────────────────────────────

    public function testWrongPasswordThrowsRuntimeException(): void
    {
        [, $userMaterial] = $this->makeUser();

        $this->expectException(\RuntimeException::class);

        $this->noteGenerator->encrypt(
            content: 'Secret content',
            password: $this->randomPassword(), // deliberately wrong
            encryptedPrivateKey: $userMaterial->encryptedPrivateKey,
            privateKeySalt: $userMaterial->privateKeySalt,
            privateKeyIv: $userMaterial->privateKeyIv,
            publicKey: $userMaterial->publicKey,
        );
    }

    // ── Corrupted key material (encrypt) ─────────────────────────────────────

    public function testCorruptedEncryptedPrivateKeyThrowsRuntimeException(): void
    {
        [$password, $userMaterial] = $this->makeUser();

        // Flip a byte in the stored blob to simulate corruption / tag mismatch.
        $corrupted = $this->flipFirstByte($userMaterial->encryptedPrivateKey);

        $this->expectException(\RuntimeException::class);

        $this->noteGenerator->encrypt(
            content: 'Test',
            password: $password,
            encryptedPrivateKey: $corrupted,
            privateKeySalt: $userMaterial->privateKeySalt,
            privateKeyIv: $userMaterial->privateKeyIv,
            publicKey: $userMaterial->publicKey,
        );
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Generates a fresh user (password + key material) for each call.
     *
     * @return array{string, \App\Crypto\UserKeyMaterial}
     */
    private function makeUser(): array
    {
        $password = $this->randomPassword();
        $userMaterial = $this->userGenerator->generate($password);

        return [$password, $userMaterial];
    }

    /**
     * Shorthand to decrypt a note with the given user's material.
     */
    private function decryptNote(NoteKeyMaterial $material, string $password, \App\Crypto\UserKeyMaterial $userMaterial): string
    {
        return $this->noteGenerator->decrypt(
            encryptedContent: $material->encryptedContent,
            contentIv: $material->contentIv,
            encryptedContentKey: $material->encryptedContentKey,
            contentKeyIv: $material->contentKeyIv,
            password: $password,
            encryptedPrivateKey: $userMaterial->encryptedPrivateKey,
            privateKeySalt: $userMaterial->privateKeySalt,
            privateKeyIv: $userMaterial->privateKeyIv,
            publicKey: $userMaterial->publicKey,
        );
    }

    /**
     * Shorthand to encrypt a note with the given user's material.
     */
    private function encryptNote(string $content, string $password, \App\Crypto\UserKeyMaterial $userMaterial): NoteKeyMaterial
    {
        return $this->noteGenerator->encrypt(
            content: $content,
            password: $password,
            encryptedPrivateKey: $userMaterial->encryptedPrivateKey,
            privateKeySalt: $userMaterial->privateKeySalt,
            privateKeyIv: $userMaterial->privateKeyIv,
            publicKey: $userMaterial->publicKey,
        );
    }

    /**
     * Generates a cryptographically random password — no hardcoded secrets.
     */
    private function randomPassword(): string
    {
        return base64_encode(random_bytes(24));
    }

    /**
     * Generates a random content string for use in statistical tests.
     */
    private function randomContent(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * Decodes a base64url (no-padding) string to raw bytes.
     */
    private function base64UrlDecode(string $input): string
    {
        $padded = str_pad(strtr($input, '-_', '+/'), (int) (ceil(strlen($input) / 4) * 4), '=');

        return (string) base64_decode($padded, strict: true);
    }

    /**
     * Flips the first byte of a base64url-encoded blob to simulate corruption.
     */
    private function flipFirstByte(string $base64url): string
    {
        $raw = $this->base64UrlDecode($base64url);
        $raw[0] = chr(ord($raw[0]) ^ 0xFF);

        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
