<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Storage;

use Linkedcode\Middleware\Csrf\Contract\CsrfTokenStorageInterface;
use Linkedcode\Middleware\Csrf\Contract\SessionInterface;

/**
 * Stores CSRF tokens inside a session using a namespaced key.
 * Does NOT touch $_SESSION directly – depends on the SessionInterface abstraction.
 */
final class SessionTokenStorage implements CsrfTokenStorageInterface
{
    private const SESSION_KEY = '_csrf_tokens';

    public function __construct(private readonly SessionInterface $session) {}

    public function store(string $tokenId, string $tokenValue): void
    {
        /** @var array<string,string> $tokens */
        $tokens = $this->session->get(self::SESSION_KEY, []);
        $tokens[$tokenId] = $tokenValue;
        $this->session->set(self::SESSION_KEY, $tokens);
    }

    public function retrieve(string $tokenId): ?string
    {
        /** @var array<string,string> $tokens */
        $tokens = $this->session->get(self::SESSION_KEY, []);
        return $tokens[$tokenId] ?? null;
    }

    public function invalidate(string $tokenId): void
    {
        /** @var array<string,string> $tokens */
        $tokens = $this->session->get(self::SESSION_KEY, []);
        unset($tokens[$tokenId]);
        $this->session->set(self::SESSION_KEY, $tokens);
    }

    public function exists(string $tokenId): bool
    {
        return $this->retrieve($tokenId) !== null;
    }
}
