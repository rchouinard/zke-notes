<?php

declare(strict_types=1);

namespace App\ApiResource;

use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\Post;
use App\State\User\UserProvider;
use App\State\User\UserRegistrationProcessor;
use App\Validator\Base64Url;
use Symfony\Component\Validator\Constraints as Assert;

#[ApiResource(
    shortName: 'User',
    operations: [
        new Post(
            uriTemplate: '/users',
            processor: UserRegistrationProcessor::class,
            security: "is_granted('PUBLIC_ACCESS')",
        ),
        new Get(
            uriTemplate: '/users/{id}',
            provider: UserProvider::class,
            security: "is_granted('ROLE_USER') and object.id === user.getId().toBase32()",
        ),
    ]
)]
class UserResource
{
    public ?string $id = null;

    #[Assert\NotBlank(groups: ['create'])]
    #[Assert\Length(min: 3, max: 180)]
    public ?string $username = null;

    #[Assert\NotBlank(groups: ['create'])]
    public ?string $password = null;

    #[Assert\NotBlank(groups: ['create'])]
    #[Base64Url]
    public ?string $publicKey = null;

    #[Assert\NotBlank(groups: ['create'])]
    #[Base64Url]
    public ?string $encryptedPrivateKey = null;

    #[Assert\NotBlank(groups: ['create'])]
    #[Assert\Length(min: 16, max: 64)]
    #[Base64Url]
    public ?string $privateKeySalt = null;

    #[Assert\NotBlank(groups: ['create'])]
    #[Assert\Length(min: 16, max: 16)]
    #[Base64Url]
    public ?string $privateKeyIv = null;
}
