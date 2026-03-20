<?php

declare(strict_types=1);

namespace App\State\Note;

use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProviderInterface;
use App\ApiResource\NoteResource;
use App\Repository\NoteRepository;
use App\Security\Voter\NoteVoter;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Uid\Ulid;

/**
 * @implements ProviderInterface<NoteResource>
 */
final class NoteItemProvider implements ProviderInterface
{
    public function __construct(
        private readonly NoteRepository $noteRepository,
        private readonly Security $security,
    ) {
    }

    /**
     * @param array<string, mixed> $uriVariables
     * @param array<string, mixed> $context
     */
    public function provide(Operation $operation, array $uriVariables = [], array $context = []): NoteResource
    {
        $id = $uriVariables['id'] ?? null;

        if (!is_string($id) || !Ulid::isValid($id)) {
            throw new NotFoundHttpException('Note not found.');
        }

        $note = $this->noteRepository->find(Ulid::fromBase32(strtoupper($id)));

        if (null === $note) {
            throw new NotFoundHttpException('Note not found.');
        }

        if (!$this->security->isGranted(NoteVoter::VIEW, $note)) {
            throw new AccessDeniedException();
        }

        return NoteProcessor::toResource($note);
    }
}
