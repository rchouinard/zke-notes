---
name: API Backend (PHP / Symfony / API Platform)
globs: ['api/**/*.php', 'api/**/*.yaml', 'api/**/*.xml', 'api/composer.json']
alwaysApply: false
---

# API Backend Rules

## Stack Versions

- PHP **8.4** (use all modern features: readonly properties, enums, fibers where appropriate, `#[Attribute]`, match expressions)
- Symfony **7.2**
- API Platform **4.x** (attribute-based configuration preferred over YAML/XML)
- FrankenPHP runtime

## PHP Standards

- Always declare `strict_types=1` at the top of every PHP file.
- Use **readonly** properties for value objects and DTOs.
- Use **PHP enums** (backed enums with `string` or `int` backing) instead of class constants for fixed sets of values.
- Follow **PSR-12** coding style enforced by `php-cs-fixer` (config at `api/.php-cs-fixer.dist.php`).
- All new classes must be in the `App\` namespace under `api/src/`.

## Symfony Conventions

- Use **PHP 8 attributes** for routing, security, validation, and serialization — not YAML/XML annotations.
- Services are **autowired and autoconfigured** by default — do not define services manually in `services.yaml` unless strictly necessary.
- Use **Symfony Security** with JWT authentication for stateless API access. The firewall is `stateless: true`.
- Passwords are hashed with Symfony's `UserPasswordHasherInterface` — never store or compare plaintext passwords.
- Use Symfony **Validator** constraints to validate all DTO/input fields. Ciphertext fields validate as non-empty base64url strings.
- Use Symfony **EventSubscriber** or API Platform **state processors/providers** for cross-cutting concerns — do not put business logic in controllers.

## API Platform Conventions

- Use `#[ApiResource]` with explicit `operations` — do not rely on default CRUD unless intentional.
- Use API Platform **state processors** for write operations and **state providers** for custom read operations.
- Use `#[ApiProperty]` to mark `encryptedContent`, `encryptedContentKey`, `encryptedPrivateKey`, `publicKey` fields as opaque blobs (`openapiContext` should describe them as `type: string, format: byte`).
- Use **serialization groups** (`#[Groups]`) to carefully control what is exposed per operation. Never expose internal fields (hashed passwords, internal flags) to the API output.
- IRI-based relations follow API Platform conventions — use `#[ApiResource]` IRIs for related resources.
- Use **pagination** on all collection endpoints.

## Security

- All routes except registration and login require authentication (`IS_AUTHENTICATED_FULLY`).
- Use **voters** for object-level authorization (e.g. a user can only read/write their own notes; a shared note can be read by the recipient).
- Never expose another user's `encryptedPrivateKey` or any private key material via the API.
- The `publicKey` field of a user IS intentionally public and may be fetched by authenticated users to enable note sharing.

## Entity Structure (expected)

```
App\Entity\User          — id (ULID), username, password, publicKey, encryptedPrivateKey, salt
App\Entity\Note          — id (ULID), owner (User), encryptedContent, encryptedContentKey, createdAt, updatedAt
App\Entity\NoteShare     — id (ULID), note (Note), recipient (User), encryptedContentKey, createdAt
```

- All entities use ULID primary keys via `doctrine.ulid_generator`.
- Timestamps use `DateTimeImmutable`.

## Error Handling

- Return RFC 7807 Problem Details for all errors (API Platform does this by default).
- Do not leak stack traces, file paths, or internal logic in production error responses.
