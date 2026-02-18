<?php

namespace Linkedcode\Middleware\Csrf;

use Linkedcode\Middleware\Csrf\Contracts\SecretResolver;
use Linkedcode\Middleware\Csrf\Contracts\TokenStorageInterface;

class CsrfTokenManager
{
    public function __construct(
        private SecretResolver $secretResolver,
        private ?TokenStorageInterface $storage = null,
        private int $ttl = 600 // default 10 minutes
    ) {}

    /**
     * Generate a CSRF token.
     */
    public function generateToken(): string
    {
        $timestamp = time();

        $payload = (string) $timestamp;

        $secret = $this->secretResolver->resolve();

        $signature = hash_hmac('sha256', $payload, $secret);

        $token = $payload . '.' . $signature;

        return base64_encode($token);
    }

    /**
     * Validate a CSRF token.
     */
    public function validateToken(string $token): bool
    {
        $decoded = base64_decode($token, true);

        if ($decoded === false) {
            return false;
        }

        $parts = explode('.', $decoded);

        if (count($parts) !== 2) {
            return false;
        }

        [$timestamp, $signature] = $parts;

        if (!ctype_digit($timestamp)) {
            return false;
        }

        $timestamp = (int) $timestamp;

        // TTL check
        if (($timestamp + $this->ttl) < time()) {
            return false;
        }

        $secret = $this->secretResolver->resolve();

        $expectedSignature = hash_hmac('sha256', (string) $timestamp, $secret);

        if (!hash_equals($expectedSignature, $signature)) {
            return false;
        }

        // Anti-replay mode (optional storage)
        if ($this->storage !== null) {

            $tokenId = hash('sha256', $signature);

            if ($this->storage->exists($tokenId)) {
                return false; // replay detected
            }

            $expiresAt = $timestamp + $this->ttl;

            $this->storage->store($tokenId, $expiresAt);
        }

        return true;
    }
}
