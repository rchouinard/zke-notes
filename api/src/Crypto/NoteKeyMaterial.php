<?php

declare(strict_types=1);

namespace App\Crypto;

/**
 * Immutable value object that carries the base64url-encoded cryptographic
 * material for a newly encrypted note.
 *
 * All fields are opaque blobs from the server's perspective; their raw byte
 * content is only meaningful to the client (SPA) that holds the private key.
 */
final readonly class NoteKeyMaterial
{
    /**
     * @param string $encryptedContent    base64url-encoded AES-256-GCM ciphertext ‖ tag
     *                                    of the note content
     * @param string $contentIv           base64url-encoded 96-bit AES-GCM IV used to
     *                                    encrypt the note content
     * @param string $encryptedContentKey base64url-encoded AES-256-GCM ciphertext ‖ tag
     *                                    of the content encryption key (CEK)
     * @param string $contentKeyIv        base64url-encoded 96-bit AES-GCM IV used to
     *                                    wrap the CEK
     */
    public function __construct(
        public readonly string $encryptedContent,
        public readonly string $contentIv,
        public readonly string $encryptedContentKey,
        public readonly string $contentKeyIv,
    ) {
    }
}
