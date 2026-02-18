<?php

namespace Linkedcode\Middleware\Csrf\Contracts;

interface TokenStorageInterface
{
    /**
     * Store a token identifier until expiration time.
     */
    public function store(string $tokenId, int $expiresAt): void;

    /**
     * Check if a token identifier was already used.
     */
    public function exists(string $tokenId): bool;

    /**
     * Remove expired tokens.
     */
    public function cleanup(): void;
}
