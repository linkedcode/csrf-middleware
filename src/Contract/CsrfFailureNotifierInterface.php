<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Contract;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Delivers a human-readable message about a CSRF failure back to the user
 * (e.g. via a session flash). Implemented by the consuming app, since the
 * message-delivery mechanism (session library, flash format, etc.) is app-specific.
 */
interface CsrfFailureNotifierInterface
{
    public function notify(ServerRequestInterface $request, string $message): void;
}
