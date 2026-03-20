<?php

declare(strict_types=1);

namespace App\Command;

use App\Crypto\NoteCryptoGeneratorInterface;
use App\Entity\Note;
use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * CLI command to create an encrypted note on behalf of an existing user.
 *
 * Because the application is zero-knowledge, all encryption is performed
 * here in the same way the SPA would do it in the browser:
 *
 *   1. The user's password is used to unwrap their stored private key via
 *      PBKDF2-SHA-256 → AES-256-GCM (matching the SPA's registration flow).
 *   2. A random AES-256-GCM content encryption key (CEK) is generated.
 *   3. The note content is encrypted with the CEK.
 *   4. The CEK is wrapped with a key derived from
 *      ECDH(userPrivate, userPublic) → HKDF-SHA-256 → AES-256-GCM.
 *   5. Only ciphertext and IV blobs are persisted — no plaintext ever reaches
 *      the database.
 *
 * Usage:
 *   php bin/console app:note:create <username> <title>
 *   php bin/console app:note:create <username> <title> --password=<password>
 *   php bin/console app:note:create <username> <title> --content=<content>
 *   php bin/console app:note:create <username> <title> --password=<p> --content=<c>
 */
#[AsCommand(
    name: 'app:note:create',
    description: 'Create an encrypted note for an existing user.',
)]
final class NoteCreateCommand extends Command
{
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly UserRepository $userRepository,
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly NoteCryptoGeneratorInterface $cryptoGenerator,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument(
                name: 'username',
                mode: InputArgument::REQUIRED,
                description: 'Username of the note owner.',
            )
            ->addArgument(
                name: 'title',
                mode: InputArgument::REQUIRED,
                description: 'Plaintext title for the note.',
            )
            ->addOption(
                name: 'password',
                shortcut: 'p',
                mode: InputOption::VALUE_REQUIRED,
                description: 'The user\'s plaintext password. Omit to be prompted interactively (recommended).',
            )
            ->addOption(
                name: 'content',
                shortcut: 'c',
                mode: InputOption::VALUE_REQUIRED,
                description: 'Plaintext note body. Omit to be prompted interactively.',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $username = trim((string) $input->getArgument('username'));
        $title = trim((string) $input->getArgument('title'));

        if ('' === $title) {
            $io->error('Title must not be empty.');

            return Command::FAILURE;
        }

        $password = $input->getOption('password');

        if (!is_string($password) || '' === $password) {
            $password = $io->askHidden('Password (input hidden)');

            if (!is_string($password) || '' === $password) {
                $io->error('A non-empty password is required.');

                return Command::FAILURE;
            }
        }

        $content = $input->getOption('content');

        if (!is_string($content) || '' === $content) {
            $content = $io->ask('Note content');

            if (!is_string($content) || '' === $content) {
                $io->error('Note content must not be empty.');

                return Command::FAILURE;
            }
        }

        $user = $this->userRepository->findOneBy(['username' => $username]);

        if (!$user instanceof User) {
            $io->error(sprintf('User "%s" not found.', $username));

            return Command::FAILURE;
        }

        if (!$this->passwordHasher->isPasswordValid($user, $password)) {
            $io->error('Invalid password.');

            return Command::FAILURE;
        }

        $io->text('Encrypting note content…');

        try {
            $keyMaterial = $this->cryptoGenerator->encrypt(
                content: $content,
                password: $password,
                encryptedPrivateKey: (string) $user->getEncryptedPrivateKey(),
                privateKeySalt: (string) $user->getPrivateKeySalt(),
                privateKeyIv: (string) $user->getPrivateKeyIv(),
                publicKey: (string) $user->getPublicKey(),
            );
        } catch (\Throwable $e) {
            $io->error(sprintf('Encryption failed: %s', $e->getMessage()));

            return Command::FAILURE;
        }

        $note = new Note();
        $note->setOwner($user);
        $note->setTitle($title);
        $note->setEncryptedContent($keyMaterial->encryptedContent);
        $note->setContentIv($keyMaterial->contentIv);
        $note->setEncryptedContentKey($keyMaterial->encryptedContentKey);
        $note->setContentKeyIv($keyMaterial->contentKeyIv);
        $note->setCreatedAt(new \DateTimeImmutable());

        $this->entityManager->persist($note);
        $this->entityManager->flush();

        $io->success(sprintf('Note "%s" created successfully for user "%s".', $title, $username));

        $io->definitionList(
            ['Note ID' => (string) $note->getId()],
            ['Owner' => $username],
            ['Title' => $title],
            ['Created at' => $note->getCreatedAt()->format(\DateTimeInterface::ATOM)],
        );

        $io->note('Note content was encrypted client-side. The plaintext and keys are NOT retained.');

        return Command::SUCCESS;
    }
}
