<?php

declare(strict_types=1);

namespace App\Tests\Unit\Command;

use App\Command\NoteCreateCommand;
use App\Crypto\NoteCryptoGeneratorInterface;
use App\Crypto\NoteKeyMaterial;
use App\Entity\Note;
use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * Unit tests for {@see NoteCreateCommand}.
 *
 * All collaborators are mocked/stubbed so no database or real crypto work is
 * performed.  Tests focus on argument/option handling, user interaction flow,
 * password verification, and correct wiring of entity fields.
 */
final class NoteCreateCommandTest extends TestCase
{
    private EntityManagerInterface&Stub $entityManager;
    private UserRepository&Stub $userRepository;
    private UserPasswordHasherInterface&Stub $passwordHasher;
    private NoteCryptoGeneratorInterface&Stub $cryptoGenerator;
    private CommandTester $tester;

    protected function setUp(): void
    {
        $this->entityManager = $this->createStub(EntityManagerInterface::class);
        $this->userRepository = $this->createStub(UserRepository::class);
        $this->passwordHasher = $this->createStub(UserPasswordHasherInterface::class);
        $this->cryptoGenerator = $this->createStub(NoteCryptoGeneratorInterface::class);

        $this->userRepository->method('findOneBy')->willReturn($this->makeUser());
        $this->passwordHasher->method('isPasswordValid')->willReturn(true);
        $this->cryptoGenerator->method('encrypt')->willReturn($this->makeNoteKeyMaterial());

        $this->rebuildTester();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function rebuildTester(): void
    {
        $command = new NoteCreateCommand(
            $this->entityManager,
            $this->userRepository,
            $this->passwordHasher,
            $this->cryptoGenerator,
        );
        $this->tester = new CommandTester($command);
    }

    private function mockEntityManager(): EntityManagerInterface&MockObject
    {
        $mock = $this->createMock(EntityManagerInterface::class);
        $this->entityManager = $mock;
        $this->rebuildTester();

        return $mock;
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

    private function makeNoteKeyMaterial(): NoteKeyMaterial
    {
        return new NoteKeyMaterial(
            encryptedContent: 'encContentBase64url',
            contentIv: 'contentIvBase64url',
            encryptedContentKey: 'encKeyBase64url',
            contentKeyIv: 'keyIvBase64url',
        );
    }

    // ── Success path ──────────────────────────────────────────────────────────

    public function testSuccessfulCreationWithAllOptions(): void
    {
        $em = $this->mockEntityManager();
        $em->expects(self::once())->method('persist')->with(self::isInstanceOf(Note::class));
        $em->expects(self::once())->method('flush');

        $exitCode = $this->tester->execute([
            'username' => 'alice',
            'title' => 'My first note',
            '--password' => 'correcthorsebatterystaple',
            '--content' => 'Some secret content.',
        ]);

        self::assertSame(Command::SUCCESS, $exitCode);
        self::assertStringContainsString('My first note', $this->tester->getDisplay());
        self::assertStringContainsString('alice', $this->tester->getDisplay());
    }

    public function testSuccessOutputContainsNoteId(): void
    {
        $this->tester->execute([
            'username' => 'alice',
            'title' => 'My note',
            '--password' => 'pass',
            '--content' => 'body',
        ]);

        // The Note ID appears as "Note ID" in the definitionList output.
        self::assertStringContainsString('Note ID', $this->tester->getDisplay());
    }

    // ── Entity field wiring ───────────────────────────────────────────────────

    public function testNoteEntityIsPopulatedFromKeyMaterial(): void
    {
        $keyMaterial = $this->makeNoteKeyMaterial();
        $persistedNote = null;

        $this->entityManager->method('persist')
            ->willReturnCallback(static function (Note $note) use (&$persistedNote): void {
                $persistedNote = $note;
            });

        $this->tester->execute([
            'username' => 'alice',
            'title' => 'Wiring test',
            '--password' => 'pass',
            '--content' => 'body',
        ]);

        /** @var Note $persistedNote */
        self::assertNotNull($persistedNote);
        self::assertSame('Wiring test', $persistedNote->getTitle());
        self::assertSame($keyMaterial->encryptedContent, $persistedNote->getEncryptedContent());
        self::assertSame($keyMaterial->contentIv, $persistedNote->getContentIv());
        self::assertSame($keyMaterial->encryptedContentKey, $persistedNote->getEncryptedContentKey());
        self::assertSame($keyMaterial->contentKeyIv, $persistedNote->getContentKeyIv());
        self::assertNotNull($persistedNote->getCreatedAt());
    }

    public function testNoteOwnerIsSetToResolvedUser(): void
    {
        $user = $this->makeUser();
        $persistedNote = null;

        // Configure collaborators BEFORE rebuilding the tester.
        $this->userRepository = $this->createStub(UserRepository::class);
        $this->userRepository->method('findOneBy')->willReturn($user);

        $this->entityManager = $this->createStub(EntityManagerInterface::class);
        $this->entityManager->method('persist')
            ->willReturnCallback(static function (Note $note) use (&$persistedNote): void {
                $persistedNote = $note;
            });

        $this->rebuildTester();

        $this->tester->execute([
            'username' => 'alice',
            'title' => 'Owner test',
            '--password' => 'pass',
            '--content' => 'body',
        ]);

        /** @var Note $persistedNote */
        self::assertNotNull($persistedNote);
        self::assertSame($user, $persistedNote->getOwner());
    }

    // ── Crypto generator wiring ───────────────────────────────────────────────

    public function testCryptoGeneratorReceivesCorrectArguments(): void
    {
        $user = $this->makeUser();
        $this->userRepository->method('findOneBy')->willReturn($user);
        $this->rebuildTester();

        $gen = $this->mockCryptoGenerator();
        $gen->expects(self::once())
            ->method('encrypt')
            ->with(
                'Secret body',
                'mypassword',
                $user->getEncryptedPrivateKey(),
                $user->getPrivateKeySalt(),
                $user->getPrivateKeyIv(),
                $user->getPublicKey(),
            )
            ->willReturn($this->makeNoteKeyMaterial());

        $this->tester->execute([
            'username' => 'alice',
            'title' => 'Wiring',
            '--password' => 'mypassword',
            '--content' => 'Secret body',
        ]);
    }

    // ── Password verification ─────────────────────────────────────────────────

    public function testInvalidPasswordReturnsFailure(): void
    {
        $this->passwordHasher = $this->createStub(UserPasswordHasherInterface::class);
        $this->passwordHasher->method('isPasswordValid')->willReturn(false);
        $this->rebuildTester();

        $em = $this->mockEntityManager();
        $em->expects(self::never())->method('flush');

        $exitCode = $this->tester->execute([
            'username' => 'alice',
            'title' => 'Note',
            '--password' => 'wrongpassword',
            '--content' => 'body',
        ]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('Invalid password', $this->tester->getDisplay());
    }

    public function testPasswordHasherIsCalledWithResolvedUser(): void
    {
        $user = $this->makeUser();
        $this->userRepository->method('findOneBy')->willReturn($user);
        $this->rebuildTester();

        $hasher = $this->mockPasswordHasher();
        $hasher->expects(self::once())
            ->method('isPasswordValid')
            ->with($user, 'mypassword')
            ->willReturn(true);

        $this->tester->execute([
            'username' => 'alice',
            'title' => 'Note',
            '--password' => 'mypassword',
            '--content' => 'body',
        ]);
    }

    // ── User not found ────────────────────────────────────────────────────────

    public function testUnknownUserReturnsFailure(): void
    {
        $this->userRepository = $this->createStub(UserRepository::class);
        $this->userRepository->method('findOneBy')->willReturn(null);
        $this->rebuildTester();

        $em = $this->mockEntityManager();
        $em->expects(self::never())->method('flush');

        $exitCode = $this->tester->execute([
            'username' => 'nobody',
            'title' => 'Note',
            '--password' => 'pass',
            '--content' => 'body',
        ]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('nobody', $this->tester->getDisplay());
    }

    // ── Empty title ───────────────────────────────────────────────────────────

    public function testEmptyTitleReturnsFailure(): void
    {
        $em = $this->mockEntityManager();
        $em->expects(self::never())->method('flush');

        $exitCode = $this->tester->execute([
            'username' => 'alice',
            'title' => '   ',
            '--password' => 'pass',
            '--content' => 'body',
        ]);

        self::assertSame(Command::FAILURE, $exitCode);
    }

    // ── Crypto exception ──────────────────────────────────────────────────────

    public function testCryptoExceptionReturnsFailure(): void
    {
        $this->cryptoGenerator = $this->createStub(NoteCryptoGeneratorInterface::class);
        $this->cryptoGenerator->method('encrypt')->willThrowException(new \RuntimeException('wrong password'));
        $this->rebuildTester();

        $em = $this->mockEntityManager();
        $em->expects(self::never())->method('flush');

        $exitCode = $this->tester->execute([
            'username' => 'alice',
            'title' => 'Note',
            '--password' => 'badpass',
            '--content' => 'body',
        ]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('wrong password', $this->tester->getDisplay());
    }

    // ── Interactive prompts ───────────────────────────────────────────────────

    public function testInteractivePasswordAndContentPromptsSucceed(): void
    {
        $em = $this->mockEntityManager();
        $em->expects(self::once())->method('flush');

        $this->tester->setInputs(['secretpassword', 'My note body goes here.']);

        $exitCode = $this->tester->execute([
            'username' => 'alice',
            'title' => 'Interactive note',
        ]);

        self::assertSame(Command::SUCCESS, $exitCode);
    }

    public function testInteractiveEmptyPasswordReturnsFailure(): void
    {
        $em = $this->mockEntityManager();
        $em->expects(self::never())->method('flush');

        $this->tester->setInputs(['', '']);

        $exitCode = $this->tester->execute([
            'username' => 'alice',
            'title' => 'Note',
        ]);

        self::assertSame(Command::FAILURE, $exitCode);
    }

    public function testInteractiveEmptyContentReturnsFailure(): void
    {
        $em = $this->mockEntityManager();
        $em->expects(self::never())->method('flush');

        $this->tester->setInputs(['secretpassword', '']);

        $exitCode = $this->tester->execute([
            'username' => 'alice',
            'title' => 'Note',
        ]);

        self::assertSame(Command::FAILURE, $exitCode);
    }
}
