<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Strategy;

use Linkedcode\Middleware\Csrf\Contract\CsrfStrategyInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Web (HTML form) strategy.
 *
 * On success : attaches 'csrf_valid' = true attribute to the request.
 * On failure : behavior depends on $failMode (see CsrfFailMode).
 */
final class WebStrategy implements CsrfStrategyInterface
{
    public const ATTRIBUTE = 'csrf_valid';

    /**
     * @param (callable(ServerRequestInterface): bool)|null $isAuthenticated
     *        Required when $failMode is UnauthenticatedOnly.
     * @param (callable(ServerRequestInterface): ?ResponseInterface)|null $onAuthenticatedFailure
     *        Called when $failMode is UnauthenticatedOnly and $isAuthenticated
     *        returns true. Falling through to null keeps the default 403.
     */
    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly string $failureMessage = 'CSRF token validation failed.',
        private readonly CsrfFailMode $failMode = CsrfFailMode::Never,
        private readonly mixed $isAuthenticated = null,
        private readonly mixed $onAuthenticatedFailure = null,
    ) {}

    public function onSuccess(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(self::ATTRIBUTE, true);
    }

    public function onFailure(ServerRequestInterface $request): ResponseInterface|null
    {
        if ($this->failMode === CsrfFailMode::Never) {
            return null;
        }

        if ($this->failMode === CsrfFailMode::UnauthenticatedOnly
            && $this->isAuthenticated !== null
            && ($this->isAuthenticated)($request)
        ) {
            $response = $this->onAuthenticatedFailure !== null
                ? ($this->onAuthenticatedFailure)($request)
                : null;

            if ($response !== null) {
                return $response;
            }
        }

        $response = $this->responseFactory->createResponse(403);
        $response->getBody()->write(
            sprintf(
                '<!DOCTYPE html><html><head><title>403 Forbidden</title></head>'
                    . '<body><h1>403 Forbidden</h1><p>%s</p></body></html>',
                htmlspecialchars($this->failureMessage, ENT_QUOTES | ENT_HTML5)
            )
        );

        return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
    }
}
