<?php

namespace Linkedcode\Middleware\Csrf;

use Linkedcode\Middleware\Csrf\Contracts\FingerprintResolver;
use Linkedcode\Middleware\Csrf\Contracts\SecretResolver;
use Linkedcode\Middleware\Csrf\Contracts\UserIdResolver;
use Psr\Http\Message\ServerRequestInterface;

final class ExtendedCsrfTokenManager
{
    public function __construct(
        private SecretResolver $secretResolver,
        private ?UserIdResolver $userIdResolver = null,
        private ?FingerprintResolver $fingerprintResolver = null,
        private int $ttl = 600
    ) {}

    public function generate(ServerRequestInterface $request): string
    {
        $timestamp = time();
        $method = strtoupper($request->getMethod());
        $path = $request->getUri()->getPath();
        $userId = $this->userIdResolver?->resolve($request) ?? '';
        $fingerprint = $this->fingerprintResolver?->resolve($request) ?? '';

        $payload = implode('|', [
            $timestamp,
            $method,
            $path,
            $userId,
            $fingerprint
        ]);

        $secret = $this->secretResolver->resolve($request);

        $signature = hash_hmac('sha256', $payload, $secret, true);

        return base64_encode(
            $payload . '|' . base64_encode($signature)
        );
    }

    public function validate(ServerRequestInterface $request, string $token): bool
    {
        $decoded = base64_decode($token, true);
        if (!$decoded) {
            return false;
        }

        $parts = explode('|', $decoded);

        if (count($parts) !== 6) {
            return false;
        }

        $signature = base64_decode(array_pop($parts), true);
        if (!$signature) {
            return false;
        }

        [$timestamp, $method, $path, $userId, $fingerprint] = $parts;

        if (!ctype_digit($timestamp)) {
            return false;
        }

        if ((time() - (int)$timestamp) > $this->ttl) {
            return false;
        }

        if ($method !== strtoupper($request->getMethod())) {
            return false;
        }

        if ($path !== $request->getUri()->getPath()) {
            return false;
        }

        $currentUserId = $this->userIdResolver?->resolve($request) ?? '';
        $currentFingerprint = $this->fingerprintResolver?->resolve($request) ?? '';

        if ($userId !== $currentUserId) {
            return false;
        }

        if ($fingerprint !== $currentFingerprint) {
            return false;
        }

        $payload = implode('|', [
            $timestamp,
            $method,
            $path,
            $userId,
            $fingerprint
        ]);

        $secret = $this->secretResolver->resolve($request);

        $expected = hash_hmac('sha256', $payload, $secret, true);

        return hash_equals($expected, $signature);
    }
}
