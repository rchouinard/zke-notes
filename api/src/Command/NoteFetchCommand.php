<?php

declare(strict_types=1);

namespace App\Command;

use App\Crypto\NoteCryptoGeneratorInterface;
use App\Entity\Note;
use App\Entity\User;
use App\Repository\NoteRepository;
use App\Repository\UserRepository;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Uid\Ulid;

/**
 * CLI command to fetch and decrypt a note on behalf of its owner.
 *
 * Because the application is zero-knowledge, decryption is performed here in
 * the same way the SPA would do it in the browser — the server never sees
 * plaintext; it only hands the ciphertext blobs to the CLI which holds the
 * password and can reconstruct the key material:
 *
 *   1. The user's password is used to unwrap their stored private key via
 *      PBKDF2-SHA-256 → AES-256-GCM.
 *   2. The CEK-unwrapping key is derived:
 *      ECDH(userPrivate, userPublic) → HKDF-SHA-256.
 *   3. The CEK is unwrapped (AES-256-GCM).
 *   4. The note content is decrypted with the CEK (AES-256-GCM).
 *
 * Usage:
 *   php bin/console app:note:fetch <username> <note-id>
 *   php bin/console app:note:fetch <username> <note-id> --password=<password>
 */
#[AsCommand(
    name: 'app:note:fetch',
    description: 'Fetch and decrypt a note for its owner.',
)]
final class NoteFetchCommand extends Command
{
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly NoteRepository $noteRepository,
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
                name: 'note-id',
                mode: InputArgument::REQUIRED,
                description: 'ULID of the note to fetch.',
            )
            ->addOption(
                name: 'password',
                shortcut: 'p',
                mode: InputOption::VALUE_REQUIRED,
                description: "The user's plaintext password. Omit to be prompted interactively (recommended).",
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $username = trim((string) $input->getArgument('username'));
        $noteIdRaw = trim((string) $input->getArgument('note-id'));

        if (!Ulid::isValid($noteIdRaw)) {
            $io->error(sprintf('"%s" is not a valid ULID.', $noteIdRaw));

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

        $user = $this->userRepository->findOneBy(['username' => $username]);

        if (!$user instanceof User) {
            $io->error(sprintf('User "%s" not found.', $username));

            return Command::FAILURE;
        }

        if (!$this->passwordHasher->isPasswordValid($user, $password)) {
            $io->error('Invalid password.');

            return Command::FAILURE;
        }

        $note = $this->noteRepository->find(Ulid::fromBase32(strtoupper($noteIdRaw)));

        if (!$note instanceof Note) {
            $io->error(sprintf('Note "%s" not found.', $noteIdRaw));

            return Command::FAILURE;
        }

        if ($note->getOwner() !== $user) {
            // Report as not-found to avoid leaking note existence to wrong users.
            $io->error(sprintf('Note "%s" not found.', $noteIdRaw));

            return Command::FAILURE;
        }

        $io->text('Decrypting note content…');

        try {
            $plaintext = $this->cryptoGenerator->decrypt(
                encryptedContent: (string) $note->getEncryptedContent(),
                contentIv: (string) $note->getContentIv(),
                encryptedContentKey: (string) $note->getEncryptedContentKey(),
                contentKeyIv: (string) $note->getContentKeyIv(),
                password: $password,
                encryptedPrivateKey: (string) $user->getEncryptedPrivateKey(),
                privateKeySalt: (string) $user->getPrivateKeySalt(),
                privateKeyIv: (string) $user->getPrivateKeyIv(),
                publicKey: (string) $user->getPublicKey(),
            );
        } catch (\Throwable $e) {
            $io->error(sprintf('Decryption failed: %s', $e->getMessage()));

            return Command::FAILURE;
        }

        $io->definitionList(
            ['Note ID' => (string) $note->getId()],
            ['Owner' => $username],
            ['Title' => $note->getTitle()],
            ['Created at' => $note->getCreatedAt()?->format(\DateTimeInterface::ATOM) ?? '—'],
            ['Updated at' => $note->getUpdatedAt()?->format(\DateTimeInterface::ATOM) ?? '—'],
        );

        $io->section('Content');
        $io->writeln($plaintext);

        return Command::SUCCESS;
    }
}
