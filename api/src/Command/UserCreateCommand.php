<?php

declare(strict_types=1);

namespace App\Command;

use App\Crypto\UserCryptoGeneratorInterface;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

#[AsCommand(
    name: 'app:user:create',
    description: 'Create a new user with a generated X25519 key pair.',
)]
final class UserCreateCommand extends Command
{
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly UserCryptoGeneratorInterface $cryptoGenerator,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument(
                name: 'username',
                mode: InputArgument::REQUIRED,
                description: 'The username for the new account (3-180 characters).',
            )
            ->addOption(
                name: 'password',
                shortcut: 'p',
                mode: InputOption::VALUE_REQUIRED,
                description: 'The plaintext password. Omit to be prompted interactively (recommended).',
            )
            ->addOption(
                name: 'admin',
                mode: InputOption::VALUE_NONE,
                description: 'Grant ROLE_ADMIN to the new user.',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $username = trim((string) $input->getArgument('username'));

        if (strlen($username) < 3 || strlen($username) > 180) {
            $io->error('Username must be between 3 and 180 characters.');

            return Command::FAILURE;
        }

        $password = $input->getOption('password');

        if (!is_string($password) || '' === $password) {
            $password = $io->askHidden('Password (input hidden)');

            if (!is_string($password) || '' === $password) {
                $io->error('A non-empty password is required.');

                return Command::FAILURE;
            }

            $confirm = $io->askHidden('Confirm password (input hidden)');

            if ($password !== $confirm) {
                $io->error('Passwords do not match.');

                return Command::FAILURE;
            }
        }

        $io->text('Generating X25519 key pair and encrypting private key...');

        try {
            $keyMaterial = $this->cryptoGenerator->generate($password);
        } catch (\Throwable $e) {
            $io->error(sprintf('Crypto generation failed: %s', $e->getMessage()));

            return Command::FAILURE;
        }

        $user = new User();
        $user->setUsername($username);
        $user->setPassword($this->passwordHasher->hashPassword($user, $password));
        $user->setPublicKey($keyMaterial->publicKey);
        $user->setEncryptedPrivateKey($keyMaterial->encryptedPrivateKey);
        $user->setPrivateKeySalt($keyMaterial->privateKeySalt);
        $user->setPrivateKeyIv($keyMaterial->privateKeyIv);

        if ($input->getOption('admin')) {
            $user->setRoles(['ROLE_ADMIN']);
        }

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $io->success(sprintf('User "%s" created successfully.', $username));

        $io->definitionList(
            ['ID' => (string) $user->getId()],
            ['Username' => $user->getUsername()],
            ['Roles' => implode(', ', $user->getRoles())],
            ['Public key (base64url)' => $keyMaterial->publicKey],
        );

        $io->note(
            'The private key is stored encrypted on the server. '.
            'The raw private key and plaintext password are NOT retained.'
        );

        return Command::SUCCESS;
    }
}
