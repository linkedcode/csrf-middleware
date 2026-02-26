<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Token;

use Linkedcode\Middleware\Csrf\Contract\CsrfTokenStorageInterface;
use Linkedcode\Middleware\Csrf\Exception\InvalidCsrfTokenException;

/**
 * Validates a signed CSRF token and removes it from storage (single-use).
 */
final class TokenValidator
{
    private const MAX_TOKEN_AGE = 3600; // seconds

    public function __construct(
        private readonly CsrfTokenStorageInterface $storage,
        private readonly TokenGenerator $generator,
        private readonly int $maxAge = self::MAX_TOKEN_AGE,
    ) {}

    /**
     * @throws InvalidCsrfTokenException when the token is absent, expired, tampered or already used.
     */
    public function validate(string $rawValue): void
    {
        $decoded = base64_decode(strtr($rawValue, '-_', '+/'), strict: true);

        if ($decoded === false) {
            throw new InvalidCsrfTokenException('Token is not valid base64.');
        }

        $parts = explode('|', $decoded, 3);

        if (count($parts) !== 3) {
            throw new InvalidCsrfTokenException('Token structure is invalid.');
        }

        [$id, $timestamp, $signature] = $parts;

        // 1. Existence check (also guards against already-used tokens)
        if (!$this->storage->exists($id)) {
            throw new InvalidCsrfTokenException('Token not found or already used.');
        }

        // 2. Integrity – stored value must match the submitted value
        $stored = $this->storage->retrieve($id);
        if (!hash_equals((string) $stored, $rawValue)) {
            throw new InvalidCsrfTokenException('Token value does not match stored value.');
        }

        // 3. Signature verification
        $expected = $this->generator->sign($id, $timestamp);
        if (!hash_equals($expected, $signature)) {
            throw new InvalidCsrfTokenException('Token signature is invalid.');
        }

        // 4. Expiry check
        if ((time() - (int) $timestamp) > $this->maxAge) {
            $this->storage->invalidate($id);
            throw new InvalidCsrfTokenException('Token has expired.');
        }

        // 5. Single-use: remove after successful validation
        $this->storage->invalidate($id);
    }

    /**
     * Returns true/false instead of throwing.
     */
    public function isValid(string $rawValue): bool
    {
        try {
            $this->validate($rawValue);
            return true;
        } catch (InvalidCsrfTokenException) {
            return false;
        }
    }
}
