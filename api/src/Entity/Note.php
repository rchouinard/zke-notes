<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\NoteRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Types\UlidType;
use Symfony\Component\Uid\Ulid;

#[ORM\Entity(repositoryClass: NoteRepository::class)]
class Note
{
    #[ORM\Id]
    #[ORM\Column(type: UlidType::NAME, unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: 'doctrine.ulid_generator')]
    private ?Ulid $id = null;

    #[ORM\ManyToOne(inversedBy: 'notes')]
    #[ORM\JoinColumn(nullable: false)]
    private ?User $owner = null;

    #[ORM\Column(length: 255)]
    private ?string $title = null;

    #[ORM\Column(type: Types::TEXT)]
    private ?string $encryptedContent = null;

    #[ORM\Column(length: 255)]
    private ?string $contentIv = null;

    #[ORM\Column(type: Types::TEXT)]
    private ?string $encryptedContentKey = null;

    #[ORM\Column(length: 255)]
    private ?string $contentKeyIv = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column(nullable: true)]
    private ?\DateTimeImmutable $updatedAt = null;

    public function getId(): ?Ulid
    {
        return $this->id;
    }

    public function getOwner(): ?User
    {
        return $this->owner;
    }

    public function setOwner(?User $owner): static
    {
        $this->owner = $owner;

        return $this;
    }

    public function getTitle(): ?string
    {
        return $this->title;
    }

    public function setTitle(string $title): static
    {
        $this->title = $title;

        return $this;
    }

    public function getEncryptedContent(): ?string
    {
        return $this->encryptedContent;
    }

    public function setEncryptedContent(string $encryptedContent): static
    {
        $this->encryptedContent = $encryptedContent;

        return $this;
    }

    public function getContentIv(): ?string
    {
        return $this->contentIv;
    }

    public function setContentIv(string $contentIv): static
    {
        $this->contentIv = $contentIv;

        return $this;
    }

    public function getEncryptedContentKey(): ?string
    {
        return $this->encryptedContentKey;
    }

    public function setEncryptedContentKey(string $encryptedContentKey): static
    {
        $this->encryptedContentKey = $encryptedContentKey;

        return $this;
    }

    public function getContentKeyIv(): ?string
    {
        return $this->contentKeyIv;
    }

    public function setContentKeyIv(string $contentKeyIv): static
    {
        $this->contentKeyIv = $contentKeyIv;

        return $this;
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeImmutable $createdAt): static
    {
        $this->createdAt = $createdAt;

        return $this;
    }

    public function getUpdatedAt(): ?\DateTimeImmutable
    {
        return $this->updatedAt;
    }

    public function setUpdatedAt(?\DateTimeImmutable $updatedAt): static
    {
        $this->updatedAt = $updatedAt;

        return $this;
    }
}
