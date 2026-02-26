<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Tests\Fixtures;

use Linkedcode\Middleware\Csrf\Contract\SessionInterface;

/**
 * In-memory session implementation used in tests.
 * Demonstrates how to implement SessionInterface without $_SESSION.
 */
final class InMemorySession implements SessionInterface
{
    /** @var array<string, mixed> */
    private array $data = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function set(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
    }

    public function remove(string $key): void
    {
        unset($this->data[$key]);
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }
}
