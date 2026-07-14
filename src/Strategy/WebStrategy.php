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
    use AuthAwareCsrfFailureTrait;

    public const ATTRIBUTE = 'csrf_valid';

    /**
     * @param string $authRequestAttribute Request attribute set by an upstream auth
     *        middleware (e.g. 'user_id') used to tell authenticated requests apart
     *        when $failMode is UnauthenticatedOnly. Requires CsrfMiddleware to run
     *        after that auth middleware in the stack.
     * @param (callable(ServerRequestInterface): ?ResponseInterface)|null $onAuthenticatedFailure
     *        Called when $failMode is UnauthenticatedOnly and $authRequestAttribute
     *        is present/truthy on the request. Falling through to null keeps the
     *        default failure response below.
     * @param (callable(ServerRequestInterface, string $message): ResponseInterface)|null $renderFailure
     *        Overrides how the default (non-delegated) failure response is built —
     *        e.g. to render the app's own styled error page instead of the bare
     *        HTML fallback. Receives the failure message.
     */
    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly string $failureMessage = 'CSRF token validation failed.',
        private readonly CsrfFailMode $failMode = CsrfFailMode::Never,
        private readonly string $authRequestAttribute = 'user_id',
        private readonly mixed $onAuthenticatedFailure = null,
        private readonly mixed $renderFailure = null,
    ) {}

    public function onSuccess(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(self::ATTRIBUTE, true);
    }

    public function onFailure(ServerRequestInterface $request): ResponseInterface|null
    {
        if ($this->isNeverFailMode()) {
            return null;
        }

        $delegated = $this->delegatedAuthenticatedFailureResponse($request);
        if ($delegated !== null) {
            return $delegated;
        }

        if ($this->renderFailure !== null) {
            return ($this->renderFailure)($request, $this->failureMessage);
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
