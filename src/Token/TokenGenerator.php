<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Token;

use InvalidArgumentException;
use Linkedcode\Middleware\Csrf\Contract\CsrfTokenStorageInterface;

/**
 * Generates cryptographically signed, single-use CSRF tokens.
 *
 * Token format (value):  base64url( id . '|' . timestamp . '|' . hmac )
 * The HMAC is computed over "id|timestamp" using the application secret.
 */
final class TokenGenerator
{
    public function __construct(
        private readonly CsrfTokenStorageInterface $storage,
        private readonly string $secret,
        private readonly string $algo = 'sha256',
    ) {
        if (strlen($this->secret) < 32) {
            throw new InvalidArgumentException(
                'CSRF secret must be at least 32 characters long.'
            );
        }
    }

    /**
     * Generate a new signed token and persist it in storage.
     */
    public function generate(): CsrfToken
    {
        $id        = $this->randomId();
        $timestamp = (string) time();
        $signature = $this->sign($id, $timestamp);

        // value = base64url( id | timestamp | signature )
        $payload = base64_encode($id . '|' . $timestamp . '|' . $signature);
        $value   = strtr($payload, '+/', '-_');

        $this->storage->store($id, $value);

        return new CsrfToken($id, $value);
    }

    /**
     * Compute HMAC over "id|timestamp".
     */
    public function sign(string $id, string $timestamp): string
    {
        return hash_hmac($this->algo, $id . '|' . $timestamp, $this->secret);
    }

    private function randomId(): string
    {
        return bin2hex(random_bytes(16));
    }
}
