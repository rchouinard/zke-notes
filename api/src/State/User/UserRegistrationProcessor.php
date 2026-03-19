<?php

declare(strict_types=1);

namespace App\State\User;

use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProcessorInterface;
use App\ApiResource\UserResource;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpKernel\Exception\UnprocessableEntityHttpException;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * @implements ProcessorInterface<UserResource, UserResource>
 */
final class UserRegistrationProcessor implements ProcessorInterface
{
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly UserPasswordHasherInterface $passwordHasher,
    ) {
    }

    /**
     * @param UserResource $data
     */
    public function process(mixed $data, Operation $operation, array $uriVariables = [], array $context = []): UserResource
    {
        if (!$data instanceof UserResource) {
            throw new UnprocessableEntityHttpException('Invalid resource type.');
        }

        $user = new User();
        $user->setUsername((string) $data->username);
        $user->setPassword(
            $this->passwordHasher->hashPassword($user, (string) $data->password)
        );
        $user->setPublicKey((string) $data->publicKey);
        $user->setEncryptedPrivateKey((string) $data->encryptedPrivateKey);
        $user->setPrivateKeySalt((string) $data->privateKeySalt);
        $user->setPrivateKeyIv((string) $data->privateKeyIv);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return self::toResource($user);
    }

    /**
     * Maps a User entity to a UserResource, intentionally omitting the password.
     */
    public static function toResource(User $user): UserResource
    {
        $resource = new UserResource();
        $resource->id = $user->getId()?->toBase32();
        $resource->username = $user->getUsername();
        $resource->publicKey = $user->getPublicKey();
        $resource->encryptedPrivateKey = $user->getEncryptedPrivateKey();
        $resource->privateKeySalt = $user->getPrivateKeySalt();
        $resource->privateKeyIv = $user->getPrivateKeyIv();

        return $resource;
    }
}
