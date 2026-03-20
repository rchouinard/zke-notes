<?php

declare(strict_types=1);

namespace App\ApiResource;

use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Delete;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\GetCollection;
use ApiPlatform\Metadata\Post;
use ApiPlatform\Metadata\Put;
use App\State\Note\NoteCollectionProvider;
use App\State\Note\NoteItemProvider;
use App\State\Note\NoteProcessor;
use App\Validator\Base64Url;
use Symfony\Component\Validator\Constraints as Assert;

#[ApiResource(
    shortName: 'Note',
    security: "is_granted('ROLE_USER')",
    operations: [
        new GetCollection(provider: NoteCollectionProvider::class),
        new Get(provider: NoteItemProvider::class),
        new Post(processor: NoteProcessor::class),
        new Put(processor: NoteProcessor::class),
        new Delete(processor: NoteProcessor::class),
    ],
)]
class NoteResource
{
    public ?string $id = null;

    #[Assert\NotBlank]
    public ?string $title = null;

    #[Assert\NotBlank]
    #[Base64Url]
    public ?string $encryptedContent = null;

    #[Assert\NotBlank]
    #[Assert\Length(min: 16, max: 16)]
    #[Base64Url]
    public ?string $contentIv = null;

    #[Assert\NotBlank]
    #[Base64Url]
    public ?string $encryptedContentKey = null;

    #[Assert\NotBlank]
    #[Assert\Length(min: 16, max: 16)]
    #[Base64Url]
    public ?string $contentKeyIv = null;

    public ?\DateTimeImmutable $createdAt = null;

    public ?\DateTimeImmutable $updatedAt = null;
}
