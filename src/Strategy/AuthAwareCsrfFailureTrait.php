<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Strategy;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Shared CsrfFailMode dispatch logic for strategies (Web, API, ...) that want
 * to treat authenticated requests differently on CSRF failure. Handles the
 * Never/Always/UnauthenticatedOnly decision; the strategy itself still owns
 * building its own default failure response (HTML, JSON, ...).
 *
 * @property-read CsrfFailMode $failMode
 * @property-read string $authRequestAttribute
 * @property-read (callable(ServerRequestInterface): ?ResponseInterface)|null $onAuthenticatedFailure
 */
trait AuthAwareCsrfFailureTrait
{
    private function isNeverFailMode(): bool
    {
        return $this->failMode === CsrfFailMode::Never;
    }

    /**
     * @return ResponseInterface|null The delegated response, or null if the
     *         strategy should fall through to its own default failure response.
     */
    private function delegatedAuthenticatedFailureResponse(ServerRequestInterface $request): ?ResponseInterface
    {
        if ($this->failMode !== CsrfFailMode::UnauthenticatedOnly) {
            return null;
        }

        if (!$request->getAttribute($this->authRequestAttribute)) {
            return null;
        }

        if ($this->onAuthenticatedFailure === null) {
            return null;
        }

        return ($this->onAuthenticatedFailure)($request);
    }
}
