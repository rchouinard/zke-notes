<?php

declare(strict_types=1);

namespace App\Security\Voter;

use App\Entity\Note;
use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * @extends Voter<string, Note>
 */
final class NoteVoter extends Voter
{
    public const string VIEW = 'NOTE_VIEW';
    public const string EDIT = 'NOTE_EDIT';
    public const string DELETE = 'NOTE_DELETE';

    /** @var list<string> */
    private const array ATTRIBUTES = [self::VIEW, self::EDIT, self::DELETE];

    protected function supports(string $attribute, mixed $subject): bool
    {
        return in_array($attribute, self::ATTRIBUTES, strict: true)
            && $subject instanceof Note;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();

        if (!$user instanceof User) {
            return false;
        }

        /** @var Note $subject */
        $owner = $subject->getOwner();

        if (null === $owner) {
            return false;
        }

        return $owner->getId()?->equals($user->getId()) ?? false;
    }
}
