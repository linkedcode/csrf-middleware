<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Contract;

/**
 * Abstraction over session storage.
 * Implementations must NOT rely on $_SESSION directly,
 * ensuring the middleware is decoupled from PHP's native session mechanism.
 */
interface SessionInterface
{
    /**
     * Retrieve a value from the session.
     */
    public function get(string $key, mixed $default = null): mixed;

    /**
     * Store a value in the session.
     */
    public function set(string $key, mixed $value): void;

    /**
     * Remove a value from the session.
     */
    public function remove(string $key): void;

    /**
     * Check whether a key exists in the session.
     */
    public function has(string $key): bool;
}
