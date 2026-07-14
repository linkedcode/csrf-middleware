<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Strategy;

/**
 * Controls when WebStrategy::onFailure() short-circuits with a response
 * vs. returning null (letting the request continue without csrf_valid).
 */
enum CsrfFailMode
{
    /** Never fail-fast: onFailure always returns null. */
    case Never;

    /** Always fail-fast: onFailure always returns a 403 response. */
    case Always;

    /**
     * Fail-fast only for unauthenticated requests. When $isAuthenticated
     * resolves true, delegates to $onAuthenticatedFailure instead of the
     * default 403 (useful for turning a stale-form CSRF failure into a
     * friendly redirect for logged-in users).
     */
    case UnauthenticatedOnly;

    /**
     * Never fail-fast: onFailure always returns null, and CsrfMiddleware
     * marks the request with 'csrf_valid' = false before letting it continue.
     * Intended for routes whose Action re-renders its own form with error
     * state, the same way it handles any other validation failure.
     */
    case SetAttribute;
}
