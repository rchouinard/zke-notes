<?php

declare(strict_types=1);

namespace App\Tests\Unit\Command;

use App\Command\UserCreateCommand;
use App\Crypto\UserCryptoGeneratorInterface;
use App\Crypto\UserKeyMaterial;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * Unit tests for {@see UserCreateCommand}.
 *
 * All collaborators are mocked so no database or crypto work is performed.
 * The tests focus on argument/option handling, user interaction flow, and the
 * correct wiring of the domain objects.
 */
final class UserCreateCommandTest extends TestCase
{
    /**
     * Default stubs shared across tests.  Tests that need to assert on
     * interactions create their own mocks inline (see helpers below).
     */
    private EntityManagerInterface&Stub $entityManager;
    private UserPasswordHasherInterface&Stub $passwordHasher;
    private UserCryptoGeneratorInterface&Stub $cryptoGenerator;
    private CommandTester $tester;

    protected function setUp(): void
    {
        // Use stubs (no expectation tracking) so PHPUnit 12 does not emit
        // "no expectations configured" notices on the shared instances.
        $this->entityManager = $this->createStub(EntityManagerInterface::class);
        $this->passwordHasher = $this->createStub(UserPasswordHasherInterface::class);
        $this->cryptoGenerator = $this->createStub(UserCryptoGeneratorInterface::class);

        $this->cryptoGenerator->method('generate')->willReturn($this->makeKeyMaterial());
        $this->passwordHasher->method('hashPassword')->willReturn('$hashed$password$');

        $this->rebuildTester();
    }

    /**
     * Rebuilds the CommandTester from the current collaborator instances.
     * Call after replacing a stub with a mock in individual tests.
     */
    private function rebuildTester(): void
    {
        $command = new UserCreateCommand($this->entityManager, $this->passwordHasher, $this->cryptoGenerator);
        $this->tester = new CommandTester($command);
    }

    /**
     * Creates a fresh EntityManagerInterface mock (with expectation support)
     * and rebuilds the command tester so it uses it.
     */
    private function mockEntityManager(): EntityManagerInterface&MockObject
    {
        $mock = $this->createMock(EntityManagerInterface::class);
        $this->entityManager = $mock;
        $this->rebuildTester();

        return $mock;
    }

    /**
     * Creates a fresh UserCryptoGeneratorInterface mock and rebuilds the tester.
     */
    private function mockCryptoGenerator(): UserCryptoGeneratorInterface&MockObject
    {
        $mock = $this->createMock(UserCryptoGeneratorInterface::class);
        $this->cryptoGenerator = $mock;
        $this->passwordHasher->method('hashPassword')->willReturn('$hashed$');
        $this->rebuildTester();

        return $mock;
    }

    /**
     * Creates a fresh UserPasswordHasherInterface mock and rebuilds the tester.
     */
    private function mockPasswordHasher(): UserPasswordHasherInterface&MockObject
    {
        $mock = $this->createMock(UserPasswordHasherInterface::class);
        $this->passwordHasher = $mock;
        $this->rebuildTester();

        return $mock;
    }

    private function makeKeyMaterial(): UserKeyMaterial
    {
        return new UserKeyMaterial(
            publicKey: 'publicKeyBase64url',
            encryptedPrivateKey: 'encryptedPrivateKeyBase64url',
            privateKeySalt: 'saltBase64url',
            privateKeyIv: 'ivBase64url',
        );
    }

    public function testSuccessfulCreationWithPasswordOption(): void
    {
        $em = $this->mockEntityManager();
        $em->expects(self::once())->method('persist')->with(self::isInstanceOf(User::class));
        $em->expects(self::once())->method('flush');

        $exitCode = $this->tester->execute([
            'username' => 'alice',
            '--password' => 'correcthorsebatterystaple',
        ]);

        self::assertSame(Command::SUCCESS, $exitCode);
        self::assertStringContainsString('alice', $this->tester->getDisplay());
    }

    public function testSuccessOutputContainsPublicKey(): void
    {
        $this->tester->execute([
            'username' => 'alice',
            '--password' => 'correcthorsebatterystaple',
        ]);

        self::assertStringContainsString('publicKeyBase64url', $this->tester->getDisplay());
    }

    public function testAdminRoleIsGrantedWhenFlagProvided(): void
    {
        $persistedUser = null;
        $em = $this->mockEntityManager();

        $em->expects(self::once())
            ->method('persist')
            ->willReturnCallback(static function (User $user) use (&$persistedUser): void {
                $persistedUser = $user;
            });

        $this->tester->execute([
            'username' => 'admin',
            '--password' => 'somepassword123',
            '--admin' => true,
        ]);

        /** @var User $persistedUser */
        self::assertNotNull($persistedUser);
        self::assertContains('ROLE_ADMIN', $persistedUser->getRoles());
    }

    public function testNormalUserDoesNotHaveAdminRole(): void
    {
        $persistedUser = null;
        $em = $this->mockEntityManager();

        $em->expects(self::once())
            ->method('persist')
            ->willReturnCallback(static function (User $user) use (&$persistedUser): void {
                $persistedUser = $user;
            });

        $this->tester->execute([
            'username' => 'bob',
            '--password' => 'somepassword123',
        ]);

        /** @var User $persistedUser */
        self::assertNotNull($persistedUser);
        self::assertNotContains('ROLE_ADMIN', $persistedUser->getRoles());
    }

    public function testCryptoGeneratorIsCalledWithPassword(): void
    {
        $gen = $this->mockCryptoGenerator();
        $gen->expects(self::once())
            ->method('generate')
            ->with('mySecret99')
            ->willReturn($this->makeKeyMaterial());

        $this->tester->execute([
            'username' => 'carol',
            '--password' => 'mySecret99',
        ]);
    }

    public function testPasswordHasherIsCalledWithPlaintextPassword(): void
    {
        $hasher = $this->mockPasswordHasher();
        $hasher->expects(self::once())
            ->method('hashPassword')
            ->with(self::isInstanceOf(User::class), 'mySecret99')
            ->willReturn('$hashed$');

        $this->tester->execute([
            'username' => 'carol',
            '--password' => 'mySecret99',
        ]);
    }

    public function testKeyMaterialIsStoredOnUser(): void
    {
        $keyMaterial = $this->makeKeyMaterial();
        $persistedUser = null;

        // Use a stub (not a mock) because we only need to capture the argument;
        // we are not asserting an expectation on the call count.
        $this->entityManager->method('persist')
            ->willReturnCallback(static function (User $user) use (&$persistedUser): void {
                $persistedUser = $user;
            });

        $this->tester->execute([
            'username' => 'dave',
            '--password' => 'pass',
        ]);

        /** @var User $persistedUser */
        self::assertNotNull($persistedUser);
        self::assertSame($keyMaterial->publicKey, $persistedUser->getPublicKey());
        self::assertSame($keyMaterial->encryptedPrivateKey, $persistedUser->getEncryptedPrivateKey());
        self::assertSame($keyMaterial->privateKeySalt, $persistedUser->getPrivateKeySalt());
        self::assertSame($keyMaterial->privateKeyIv, $persistedUser->getPrivateKeyIv());
    }

    public function testInteractivePasswordPromptSucceeds(): void
    {
        $em = $this->mockEntityManager();
        $em->expects(self::once())->method('flush');

        $this->tester->setInputs(['secretPassword1!', 'secretPassword1!']);

        $exitCode = $this->tester->execute(['username' => 'eve']);

        self::assertSame(Command::SUCCESS, $exitCode);
    }

    public function testInteractivePasswordMismatchReturnsFailure(): void
    {
        $em = $this->mockEntityManager();
        $em->expects(self::never())->method('flush');

        $this->tester->setInputs(['password1', 'password2']);

        $exitCode = $this->tester->execute(['username' => 'eve']);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('do not match', $this->tester->getDisplay());
    }

    public function testInteractiveEmptyPasswordReturnsFailure(): void
    {
        $em = $this->mockEntityManager();
        $em->expects(self::never())->method('flush');

        $this->tester->setInputs(['', '']);

        $exitCode = $this->tester->execute(['username' => 'eve']);

        self::assertSame(Command::FAILURE, $exitCode);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('provideInvalidUsernames')]
    public function testShortOrLongUsernameReturnsFailure(string $username): void
    {
        $em = $this->mockEntityManager();
        $em->expects(self::never())->method('flush');

        $exitCode = $this->tester->execute([
            'username' => $username,
            '--password' => 'validpassword',
        ]);

        self::assertSame(Command::FAILURE, $exitCode);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function provideInvalidUsernames(): array
    {
        return [
            'too short (1 char)' => ['a'],
            'too short (2 chars)' => ['ab'],
            'too long (181 chars)' => [str_repeat('x', 181)],
        ];
    }

    public function testCryptoExceptionReturnsFailure(): void
    {
        // Use the shared stub — we only need to configure a throw, not assert call count.
        $this->cryptoGenerator->method('generate')->willThrowException(new \RuntimeException('sodium error'));

        $em = $this->mockEntityManager();
        $em->expects(self::never())->method('flush');

        $exitCode = $this->tester->execute([
            'username' => 'frank',
            '--password' => 'somepassword',
        ]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('sodium error', $this->tester->getDisplay());
    }
}
