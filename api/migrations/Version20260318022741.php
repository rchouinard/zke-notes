<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20260318022741 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Create user and note tables';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE note (id UUID NOT NULL, title VARCHAR(255) NOT NULL, encrypted_content TEXT NOT NULL, content_iv VARCHAR(255) NOT NULL, encrypted_content_key TEXT NOT NULL, content_key_iv VARCHAR(255) NOT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, updated_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, owner_id UUID NOT NULL, PRIMARY KEY(id))');
        $this->addSql('CREATE INDEX IDX_CFBDFA147E3C61F9 ON note (owner_id)');
        $this->addSql('CREATE TABLE "user" (id UUID NOT NULL, username VARCHAR(180) NOT NULL, roles JSON NOT NULL, password VARCHAR(255) NOT NULL, public_key VARCHAR(255) NOT NULL, encrypted_private_key VARCHAR(255) NOT NULL, private_key_salt VARCHAR(255) NOT NULL, private_key_iv VARCHAR(255) NOT NULL, PRIMARY KEY(id))');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_IDENTIFIER_USERNAME ON "user" (username)');
        $this->addSql('ALTER TABLE note ADD CONSTRAINT FK_CFBDFA147E3C61F9 FOREIGN KEY (owner_id) REFERENCES "user" (id) NOT DEFERRABLE INITIALLY IMMEDIATE');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE note DROP CONSTRAINT FK_CFBDFA147E3C61F9');
        $this->addSql('DROP TABLE note');
        $this->addSql('DROP TABLE "user"');
    }
}
