<?php

namespace Linkedcode\Middleware\Csrf;

use Linkedcode\Middleware\Csrf\Contracts\SecretResolver;
use Linkedcode\Middleware\Csrf\Contracts\TokenStorageInterface;
use Psr\Http\Message\ServerRequestInterface;

final class CsrfTokenManager
{
    public function __construct(
        private SecretResolver $secretResolver,
        private ?TokenStorageInterface $storage = null,
        private int $ttl = 600
    ) {}

    public function generate(ServerRequestInterface $request, ?string $method = null): string
    {
        $method ??= strtoupper($request->getMethod());
        $timestamp = time();
        $path = $request->getUri()->getPath();

        $payload = implode('|', [
            $timestamp,
            $method,
            $path
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

        if (count($parts) !== 4) {
            return false;
        }

        $signature = base64_decode(array_pop($parts), true);
        if (!$signature) {
            return false;
        }

        [$timestamp, $method, $path] = $parts;

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

        $payload = implode('|', [$timestamp, $method, $path]);

        $secret = $this->secretResolver->resolve($request);

        $expected = hash_hmac('sha256', $payload, $secret, true);;

        if (!hash_equals($expected, $signature)) {
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
