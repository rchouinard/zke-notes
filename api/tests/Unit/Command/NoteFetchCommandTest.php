<?php

declare(strict_types=1);

namespace App\Tests\Unit\Command;

use App\Command\NoteFetchCommand;
use App\Crypto\NoteCryptoGeneratorInterface;
use App\Entity\Note;
use App\Entity\User;
use App\Repository\NoteRepository;
use App\Repository\UserRepository;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Uid\Ulid;

/**
 * Unit tests for {@see NoteFetchCommand}.
 *
 * All collaborators are stubbed/mocked so no database or real crypto work is
 * performed. Tests cover argument validation, user/note resolution, ownership
 * enforcement, password verification, decryption wiring, and output rendering.
 */
final class NoteFetchCommandTest extends TestCase
{
    /** A fixed valid ULID used as the default note ID across tests. */
    private const NOTE_ID = '01JFAKE0FAKE1FAKE2FAKE3FAK';

    private UserRepository&Stub $userRepository;
    private NoteRepository&Stub $noteRepository;
    private UserPasswordHasherInterface&Stub $passwordHasher;
    private NoteCryptoGeneratorInterface&Stub $cryptoGenerator;
    private CommandTester $tester;

    protected function setUp(): void
    {
        $this->userRepository = $this->createStub(UserRepository::class);
        $this->noteRepository = $this->createStub(NoteRepository::class);
        $this->passwordHasher = $this->createStub(UserPasswordHasherInterface::class);
        $this->cryptoGenerator = $this->createStub(NoteCryptoGeneratorInterface::class);

        $user = $this->makeUser();
        $this->userRepository->method('findOneBy')->willReturn($user);
        $this->noteRepository->method('find')->willReturn($this->makeNote($user));
        $this->passwordHasher->method('isPasswordValid')->willReturn(true);
        $this->cryptoGenerator->method('decrypt')->willReturn('Decrypted note body.');

        $this->rebuildTester();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function rebuildTester(): void
    {
        $command = new NoteFetchCommand(
            $this->userRepository,
            $this->noteRepository,
            $this->passwordHasher,
            $this->cryptoGenerator,
        );
        $this->tester = new CommandTester($command);
    }

    private function mockPasswordHasher(): UserPasswordHasherInterface&MockObject
    {
        $mock = $this->createMock(UserPasswordHasherInterface::class);
        $this->passwordHasher = $mock;
        $this->rebuildTester();

        return $mock;
    }

    private function mockCryptoGenerator(): NoteCryptoGeneratorInterface&MockObject
    {
        $mock = $this->createMock(NoteCryptoGeneratorInterface::class);
        $this->cryptoGenerator = $mock;
        $this->rebuildTester();

        return $mock;
    }

    private function makeUser(): User
    {
        $user = new User();
        $user->setUsername('alice');
        $user->setPassword('$hashed$');
        $user->setPublicKey('publicKeyBase64url');
        $user->setEncryptedPrivateKey('encPrivKeyBase64url');
        $user->setPrivateKeySalt('saltBase64url');
        $user->setPrivateKeyIv('ivBase64url');

        return $user;
    }

    private function makeNote(User $owner): Note
    {
        $note = new Note();
        $note->setOwner($owner);
        $note->setTitle('My Secret Note');
        $note->setEncryptedContent('encContentBase64url');
        $note->setContentIv('contentIvBase64url');
        $note->setEncryptedContentKey('encKeyBase64url');
        $note->setContentKeyIv('keyIvBase64url');
        $note->setCreatedAt(new \DateTimeImmutable('2024-01-01T12:00:00Z'));

        return $note;
    }

    private function execute(string $username = 'alice', string $noteId = self::NOTE_ID, string $password = 'secret'): int
    {
        return $this->tester->execute([
            'username' => $username,
            'note-id' => $noteId,
            '--password' => $password,
        ]);
    }

    // ── Success path ──────────────────────────────────────────────────────────

    public function testSuccessfulFetchReturnsSuccessCode(): void
    {
        self::assertSame(Command::SUCCESS, $this->execute());
    }

    public function testOutputContainsTitleAndOwner(): void
    {
        $this->execute();
        $display = $this->tester->getDisplay();

        self::assertStringContainsString('My Secret Note', $display);
        self::assertStringContainsString('alice', $display);
    }

    public function testOutputContainsDecryptedContent(): void
    {
        $this->execute();

        self::assertStringContainsString('Decrypted note body.', $this->tester->getDisplay());
    }

    public function testOutputContainsMetadata(): void
    {
        $this->execute();
        $display = $this->tester->getDisplay();

        self::assertStringContainsString('Note ID', $display);
        self::assertStringContainsString('Created at', $display);
        self::assertStringContainsString('Updated at', $display);
    }

    // ── Crypto generator wiring ───────────────────────────────────────────────

    public function testCryptoGeneratorReceivesCorrectArguments(): void
    {
        $user = $this->makeUser();
        $note = $this->makeNote($user);

        $this->userRepository = $this->createStub(UserRepository::class);
        $this->userRepository->method('findOneBy')->willReturn($user);
        $this->noteRepository = $this->createStub(NoteRepository::class);
        $this->noteRepository->method('find')->willReturn($note);
        $this->rebuildTester();

        $gen = $this->mockCryptoGenerator();
        $gen->expects(self::once())
            ->method('decrypt')
            ->with(
                $note->getEncryptedContent(),
                $note->getContentIv(),
                $note->getEncryptedContentKey(),
                $note->getContentKeyIv(),
                'mypassword',
                $user->getEncryptedPrivateKey(),
                $user->getPrivateKeySalt(),
                $user->getPrivateKeyIv(),
                $user->getPublicKey(),
            )
            ->willReturn('plaintext');

        $this->tester->execute([
            'username' => 'alice',
            'note-id' => self::NOTE_ID,
            '--password' => 'mypassword',
        ]);
    }

    // ── Password verification ─────────────────────────────────────────────────

    public function testInvalidPasswordReturnsFailure(): void
    {
        $this->passwordHasher = $this->createStub(UserPasswordHasherInterface::class);
        $this->passwordHasher->method('isPasswordValid')->willReturn(false);
        $this->rebuildTester();

        self::assertSame(Command::FAILURE, $this->execute());
        self::assertStringContainsString('Invalid password', $this->tester->getDisplay());
    }

    public function testPasswordHasherIsCalledWithResolvedUser(): void
    {
        $user = $this->makeUser();
        $this->userRepository = $this->createStub(UserRepository::class);
        $this->userRepository->method('findOneBy')->willReturn($user);
        $this->rebuildTester();

        $hasher = $this->mockPasswordHasher();
        $hasher->expects(self::once())
            ->method('isPasswordValid')
            ->with($user, 'mypassword')
            ->willReturn(true);

        $this->tester->execute([
            'username' => 'alice',
            'note-id' => self::NOTE_ID,
            '--password' => 'mypassword',
        ]);
    }

    // ── User not found ────────────────────────────────────────────────────────

    public function testUnknownUserReturnsFailure(): void
    {
        $this->userRepository = $this->createStub(UserRepository::class);
        $this->userRepository->method('findOneBy')->willReturn(null);
        $this->rebuildTester();

        self::assertSame(Command::FAILURE, $this->execute());
        self::assertStringContainsString('alice', $this->tester->getDisplay());
    }

    // ── Note not found ────────────────────────────────────────────────────────

    public function testUnknownNoteReturnsFailure(): void
    {
        $this->noteRepository = $this->createStub(NoteRepository::class);
        $this->noteRepository->method('find')->willReturn(null);
        $this->rebuildTester();

        self::assertSame(Command::FAILURE, $this->execute());
        self::assertStringContainsString(self::NOTE_ID, $this->tester->getDisplay());
    }

    // ── Ownership enforcement ─────────────────────────────────────────────────

    public function testNoteOwnedByDifferentUserReturnsFailure(): void
    {
        $otherUser = $this->makeUser();
        $otherUser->setUsername('bob');
        // Note belongs to otherUser, but the command is run as alice.
        $this->noteRepository = $this->createStub(NoteRepository::class);
        $this->noteRepository->method('find')->willReturn($this->makeNote($otherUser));
        $this->rebuildTester();

        self::assertSame(Command::FAILURE, $this->execute());
    }

    public function testOwnershipErrorDoesNotLeakNoteExistence(): void
    {
        // Error message must look the same as "note not found" to avoid oracle.
        $otherUser = $this->makeUser();
        $otherUser->setUsername('bob');
        $this->noteRepository = $this->createStub(NoteRepository::class);
        $this->noteRepository->method('find')->willReturn($this->makeNote($otherUser));
        $this->rebuildTester();

        $this->execute();

        self::assertStringContainsString(self::NOTE_ID, $this->tester->getDisplay());
        self::assertStringNotContainsString('bob', $this->tester->getDisplay());
    }

    // ── Invalid ULID ─────────────────────────────────────────────────────────

    public function testInvalidUlidReturnsFailure(): void
    {
        self::assertSame(Command::FAILURE, $this->execute(noteId: 'not-a-ulid'));
    }

    public function testInvalidUlidErrorMessageContainsInputValue(): void
    {
        $this->execute(noteId: 'not-a-ulid');

        self::assertStringContainsString('not-a-ulid', $this->tester->getDisplay());
    }

    // ── Decryption failure ────────────────────────────────────────────────────

    public function testDecryptionExceptionReturnsFailure(): void
    {
        $this->cryptoGenerator = $this->createStub(NoteCryptoGeneratorInterface::class);
        $this->cryptoGenerator->method('decrypt')->willThrowException(new \RuntimeException('tag mismatch'));
        $this->rebuildTester();

        self::assertSame(Command::FAILURE, $this->execute());
        self::assertStringContainsString('tag mismatch', $this->tester->getDisplay());
    }

    // ── Interactive password prompt ───────────────────────────────────────────

    public function testInteractivePasswordPromptSucceeds(): void
    {
        $this->tester->setInputs(['secretpassword']);

        $exitCode = $this->tester->execute([
            'username' => 'alice',
            'note-id' => self::NOTE_ID,
        ]);

        self::assertSame(Command::SUCCESS, $exitCode);
    }

    public function testInteractiveEmptyPasswordReturnsFailure(): void
    {
        $this->tester->setInputs(['']);

        $exitCode = $this->tester->execute([
            'username' => 'alice',
            'note-id' => self::NOTE_ID,
        ]);

        self::assertSame(Command::FAILURE, $exitCode);
    }

    // ── ULID lookup is normalised to uppercase ────────────────────────────────

    public function testLowercaseUlidIsAccepted(): void
    {
        // The ULID NOTE_ID in lowercase should still be accepted and resolved.
        $lowercaseId = strtolower(self::NOTE_ID);

        self::assertSame(Command::SUCCESS, $this->execute(noteId: $lowercaseId));
    }
}
