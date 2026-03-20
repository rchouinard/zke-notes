<?php

declare(strict_types=1);

namespace App\State\Note;

use ApiPlatform\Metadata\Delete;
use ApiPlatform\Metadata\Operation;
use ApiPlatform\Metadata\Post;
use ApiPlatform\State\ProcessorInterface;
use App\ApiResource\NoteResource;
use App\Entity\Note;
use App\Entity\User;
use App\Repository\NoteRepository;
use App\Security\Voter\NoteVoter;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\HttpKernel\Exception\UnprocessableEntityHttpException;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Uid\Ulid;

/**
 * @implements ProcessorInterface<NoteResource, NoteResource|null>
 */
final class NoteProcessor implements ProcessorInterface
{
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly NoteRepository $noteRepository,
        private readonly Security $security,
    ) {
    }

    /**
     * @param NoteResource         $data
     * @param array<string, mixed> $uriVariables
     * @param array<string, mixed> $context
     */
    public function process(mixed $data, Operation $operation, array $uriVariables = [], array $context = []): ?NoteResource
    {
        if (!$data instanceof NoteResource) {
            throw new UnprocessableEntityHttpException('Invalid resource type.');
        }

        if ($operation instanceof Delete) {
            return $this->processDelete($uriVariables);
        }

        if ($operation instanceof Post) {
            return $this->processCreate($data);
        }

        return $this->processUpdate($data, $uriVariables);
    }

    /**
     * Creates a new Note and returns the persisted resource.
     */
    private function processCreate(NoteResource $data): NoteResource
    {
        $user = $this->security->getUser();

        if (!$user instanceof User) {
            throw new UnauthorizedHttpException('Bearer', 'Authentication required.');
        }

        $note = new Note();
        $note->setOwner($user);
        $note->setCreatedAt(new \DateTimeImmutable());

        $this->applyResourceToEntity($data, $note);

        $this->entityManager->persist($note);
        $this->entityManager->flush();

        return self::toResource($note);
    }

    /**
     * Replaces ciphertext fields on an existing Note and returns the updated resource.
     *
     * @param array<string, mixed> $uriVariables
     */
    private function processUpdate(NoteResource $data, array $uriVariables): NoteResource
    {
        $note = $this->resolveNote($uriVariables);

        if (!$this->security->isGranted(NoteVoter::EDIT, $note)) {
            throw new AccessDeniedException();
        }

        $this->applyResourceToEntity($data, $note);
        $note->setUpdatedAt(new \DateTimeImmutable());

        $this->entityManager->flush();

        return self::toResource($note);
    }

    /**
     * Deletes a Note. Returns null so API Platform emits a 204 No Content response.
     *
     * @param array<string, mixed> $uriVariables
     */
    private function processDelete(array $uriVariables): null
    {
        $note = $this->resolveNote($uriVariables);

        if (!$this->security->isGranted(NoteVoter::DELETE, $note)) {
            throw new AccessDeniedException();
        }

        $this->entityManager->remove($note);
        $this->entityManager->flush();

        return null;
    }

    /**
     * Copies writable ciphertext fields from a NoteResource onto a Note entity.
     * Server-controlled fields (owner, createdAt, updatedAt) are never overwritten here.
     */
    private function applyResourceToEntity(NoteResource $resource, Note $note): void
    {
        $note->setEncryptedContent((string) $resource->encryptedContent);
        $note->setContentIv((string) $resource->contentIv);
        $note->setEncryptedContentKey((string) $resource->encryptedContentKey);
        $note->setContentKeyIv((string) $resource->contentKeyIv);
    }

    /**
     * Resolves a Note entity from URI variables, throwing 404 if not found.
     *
     * @param array<string, mixed> $uriVariables
     */
    private function resolveNote(array $uriVariables): Note
    {
        $id = $uriVariables['id'] ?? null;

        if (!is_string($id) || !Ulid::isValid($id)) {
            throw new NotFoundHttpException('Note not found.');
        }

        $note = $this->noteRepository->find(Ulid::fromBase32(strtoupper($id)));

        if (null === $note) {
            throw new NotFoundHttpException('Note not found.');
        }

        return $note;
    }

    /**
     * Maps a Note entity to a NoteResource for API output.
     */
    public static function toResource(Note $note): NoteResource
    {
        $resource = new NoteResource();
        $resource->id = $note->getId()?->toBase32();
        $resource->title = $note->getTitle();
        $resource->encryptedContent = $note->getEncryptedContent();
        $resource->contentIv = $note->getContentIv();
        $resource->encryptedContentKey = $note->getEncryptedContentKey();
        $resource->contentKeyIv = $note->getContentKeyIv();
        $resource->createdAt = $note->getCreatedAt();
        $resource->updatedAt = $note->getUpdatedAt();

        return $resource;
    }
}
