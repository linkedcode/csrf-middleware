<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Contract;

/**
 * Contract for reading and writing CSRF tokens.
 * Allows swapping session backends without touching middleware logic.
 */
interface CsrfTokenStorageInterface
{
    /**
     * Persist a token value keyed by its ID.
     */
    public function store(string $tokenId, string $tokenValue): void;

    /**
     * Retrieve a stored token value by ID, or null if not found.
     */
    public function retrieve(string $tokenId): ?string;

    /**
     * Remove the token from storage (single-use enforcement).
     */
    public function invalidate(string $tokenId): void;

    /**
     * Check if a token ID has been stored.
     */
    public function exists(string $tokenId): bool;
}
