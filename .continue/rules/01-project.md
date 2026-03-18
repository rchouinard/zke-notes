---
name: Project Overview & Shared Conventions
alwaysApply: true
---

# Project: Zero-Knowledge Encrypted Notes

## Application Purpose

A notes application where all user note content is encrypted client-side before ever reaching the server. The server stores only ciphertext and public key material — it never has access to plaintext note content or private keys.

## Monorepo Structure

- `/api` — PHP 8.4, Symfony 7.2, API Platform 4, FrankenPHP, Postgres
- `/spa` — TypeScript, Vue 3, Quasar 2, Pinia, Axios
- `compose.yaml` / `compose.override.yaml` / `compose.prod.yaml` — Docker Compose stack

## Core Architecture Principles

- **Zero-Knowledge**: The server must NEVER receive or store plaintext note content or user private keys.
- **Client-side crypto**: All encryption and decryption happens exclusively in the SPA using the Web Crypto API.
- **Asymmetric sharing**: Notes are shared between users by re-encrypting the note's symmetric key with the recipient's public key.
- **API is data transport only**: The API stores, retrieves, and relays ciphertext and key material — it does not interpret note content.

## Entity Identifiers

- All entity IDs use ULID (Symfony `UlidType`, `doctrine.ulid_generator`). Never use auto-increment integers for IDs.

## General Code Style

- Prefer explicit types everywhere (PHP strict types, TypeScript strict mode).
- No magic strings — use constants or enums.
- All public API surface (PHP classes, TypeScript functions/stores) must have doc comments.
- Keep functions and methods small and single-purpose.
- Validate all inputs at the API boundary; never trust client-supplied data on the server except opaque ciphertext/key blobs.
