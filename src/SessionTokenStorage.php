<?php

namespace Linkedcode\Middleware\Csrf;

use Linkedcode\Middleware\Csrf\Contracts\SessionInterface;
use Linkedcode\Middleware\Csrf\Contracts\TokenStorageInterface;

class SessionTokenStorage implements TokenStorageInterface
{
    private const SESSION_KEY = '_csrf_used_tokens';

    public function __construct(
        private SessionInterface $session
    ) {}

    public function store(string $tokenId, int $expiresAt): void
    {
        $tokens = $this->session->get(self::SESSION_KEY, []);

        $tokens[$tokenId] = $expiresAt;

        $this->session->set(self::SESSION_KEY, $tokens);
    }

    public function exists(string $tokenId): bool
    {
        $tokens = $this->session->get(self::SESSION_KEY, []);

        if (!isset($tokens[$tokenId])) {
            return false;
        }

        if ($tokens[$tokenId] < time()) {
            unset($tokens[$tokenId]);
            $this->session->set(self::SESSION_KEY, $tokens);
            return false;
        }

        return true;
    }

    public function cleanup(): void
    {
        $tokens = $this->session->get(self::SESSION_KEY, []);
        $now = time();

        foreach ($tokens as $id => $expiresAt) {
            if ($expiresAt < $now) {
                unset($tokens[$id]);
            }
        }

        $this->session->set(self::SESSION_KEY, $tokens);
    }
}
