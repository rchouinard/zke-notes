<?php

declare(strict_types=1);

namespace App\State\User;

use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProviderInterface;
use App\ApiResource\UserResource;
use App\Repository\UserRepository;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Uid\Ulid;

/**
 * @implements ProviderInterface<UserResource>
 */
final class UserProvider implements ProviderInterface
{
    public function __construct(
        private readonly UserRepository $userRepository,
    ) {
    }

    /**
     * @param array<string, mixed> $uriVariables
     * @param array<string, mixed> $context
     */
    public function provide(Operation $operation, array $uriVariables = [], array $context = []): UserResource
    {
        $id = $uriVariables['id'] ?? null;

        if (!is_string($id) || !Ulid::isValid($id)) {
            throw new NotFoundHttpException('User not found.');
        }

        $user = $this->userRepository->find(Ulid::fromBase32(strtoupper($id)));

        if (null === $user) {
            throw new NotFoundHttpException('User not found.');
        }

        return UserRegistrationProcessor::toResource($user);
    }
}
