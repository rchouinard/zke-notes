---
name: Data Layer (Doctrine / PostgreSQL / Migrations)
globs:
    [
        'api/src/Entity/**',
        'api/src/Repository/**',
        'api/migrations/**',
        'api/config/packages/doctrine.yaml',
    ]
alwaysApply: false
---

# Data Layer Rules

## Doctrine ORM

- Use **PHP 8 attribute** mapping (`#[ORM\...]`) exclusively — no XML or YAML mappings.
- All entities live in `api/src/Entity/` and use the `App\Entity` namespace.
- All primary keys are **ULID** using `UlidType::NAME` and `doctrine.ulid_generator`. Never use `SERIAL` or auto-increment integers.
- Use `DateTimeImmutable` for all timestamp fields (`createdAt`, `updatedAt`). Use Doctrine lifecycle callbacks or a Symfony event subscriber to set them automatically.
- Encrypted blob columns (`encryptedContent`, `encryptedContentKey`, `encryptedPrivateKey`) are stored as `TEXT` columns — use `#[ORM\Column(type: 'text')]`.
- The `publicKey` field is stored as `TEXT`, indexed for lookup, unique per user.
- The `salt` field (PBKDF2 salt) is stored as `TEXT`, unique per user.

## Relationships

- `Note` has a `ManyToOne` to `User` (owner). Cascade delete notes when a user is deleted.
- `NoteShare` has `ManyToOne` to `Note` and `ManyToOne` to `User` (recipient). Unique constraint on `(note, recipient)`. Cascade delete shares when a note is deleted.

## Repository Pattern

- Each entity has a repository in `api/src/Repository/` extending `ServiceEntityRepository`.
- Repositories contain all query logic — do not write DQL/QueryBuilder in entities, processors, or controllers.
- Repository methods return typed results (use PHP 8 return type hints, nullable, or collections).

## Migrations

- Always generate migrations using `doctrine:migrations:diff` after modifying entities.
- **Never** edit generated migration files after they have been committed/run in any environment.
- Migration descriptions must be meaningful (update `getDescription()` in the migration class).
- Do not use `doctrine:schema:update --force` in any environment.
- Migrations must be reversible (`down()` method must be implemented).

## PostgreSQL Specifics

- Target PostgreSQL **16** (as set in `compose.yaml`).
- Use `uuid`-style ULIDs stored via Symfony's `UlidType` (which maps to `char(26)` on this platform).
- Prefer database-level unique constraints (`#[ORM\UniqueConstraint]`) over application-level uniqueness checks alone.
- Use `TEXT` for variable-length encrypted blobs — do not impose arbitrary `VARCHAR` length limits on ciphertext.
