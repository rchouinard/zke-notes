<?php

declare(strict_types=1);

namespace App\State\Note;

use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProviderInterface;
use App\ApiResource\NoteResource;
use App\Entity\User;
use App\Repository\NoteRepository;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

/**
 * @implements ProviderInterface<NoteResource>
 */
final class NoteCollectionProvider implements ProviderInterface
{
    public function __construct(
        private readonly NoteRepository $noteRepository,
        private readonly Security $security,
    ) {
    }

    /**
     * @param array<string, mixed> $uriVariables
     * @param array<string, mixed> $context
     *
     * @return list<NoteResource>
     */
    public function provide(Operation $operation, array $uriVariables = [], array $context = []): array
    {
        $user = $this->security->getUser();

        if (!$user instanceof User) {
            throw new UnauthorizedHttpException('Bearer', 'Authentication required.');
        }

        $notes = $this->noteRepository->findBy(['owner' => $user]);

        return array_map(NoteProcessor::toResource(...), $notes);
    }
}
