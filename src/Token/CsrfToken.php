<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Token;

/**
 * Immutable value object representing a CSRF token.
 *
 * A token is composed of:
 *  - id    : a random identifier stored server-side (key in storage)
 *  - value : the signed payload sent to the client (id.timestamp.signature)
 */
final class CsrfToken
{
    public function __construct(
        private readonly string $id,
        private readonly string $value,
    ) {}

    public function getId(): string
    {
        return $this->id;
    }

    /**
     * The signed string that is embedded in forms / headers.
     */
    public function getValue(): string
    {
        return $this->value;
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
