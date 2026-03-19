<?php

declare(strict_types=1);

namespace App\Command;

use App\Repository\UserRepository;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\TableStyle;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'app:user:list',
    description: 'Lists application users.',
)]
final class UserListCommand extends Command
{
    public function __construct(
        private readonly UserRepository $userRepository,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $users = $this->userRepository->findAll();

        $table = $io->createTable()
            ->setHeaderTitle('Users')
            ->setHeaders(['ID', 'Username', 'Note Count']);

        foreach ($users as $user) {
            $table->addRow([(string) $user->getId(), $user->getUsername(), $user->getNotes()->count()]);
        }

        $style = (new TableStyle())->setPadType(\STR_PAD_LEFT);
        $table->setColumnStyle(2, $style);

        $table->render();

        return Command::SUCCESS;
    }
}
