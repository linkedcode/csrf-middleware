<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Strategy;

use Linkedcode\Middleware\Csrf\Contract\CsrfStrategyInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * API / AJAX strategy.
 *
 * On success : attaches 'csrf_valid' = true attribute to the request.
 * On failure : behavior depends on $failMode (see CsrfFailMode); defaults to
 *              an HTTP 403 JSON response.
 *
 * The token for API calls is expected in the request header X-CSRF-Token
 * or in the JSON body field "_csrf_token".
 */
final class ApiStrategy implements CsrfStrategyInterface
{
    use AuthAwareCsrfFailureTrait;

    public const ATTRIBUTE = 'csrf_valid';

    /**
     * @param string $authRequestAttribute Request attribute set by an upstream auth
     *        middleware (e.g. 'user_id') used to tell authenticated requests apart
     *        when $failMode is UnauthenticatedOnly.
     * @param (callable(ServerRequestInterface): ?ResponseInterface)|null $onAuthenticatedFailure
     *        Called when $failMode is UnauthenticatedOnly and $authRequestAttribute
     *        is present/truthy on the request. Falling through to null keeps the
     *        default 403 JSON response.
     */
    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly string $failureMessage = 'CSRF token validation failed.',
        private readonly CsrfFailMode $failMode = CsrfFailMode::Always,
        private readonly string $authRequestAttribute = 'user_id',
        private readonly mixed $onAuthenticatedFailure = null,
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

        $body = json_encode([
            'error'   => 'forbidden',
            'message' => $this->failureMessage,
            'code'    => 403,
        ], JSON_THROW_ON_ERROR);

        $response = $this->responseFactory->createResponse(403);
        $response->getBody()->write($body);

        return $response->withHeader('Content-Type', 'application/json');
    }
}
