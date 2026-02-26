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
 * On failure : returns an HTTP 403 JSON response.
 *
 * The token for API calls is expected in the request header X-CSRF-Token
 * or in the JSON body field "_csrf_token".
 */
final class ApiStrategy implements CsrfStrategyInterface
{
    public const ATTRIBUTE = 'csrf_valid';

    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly string $failureMessage = 'CSRF token validation failed.'
    ) {}

    public function onSuccess(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(self::ATTRIBUTE, true);
    }

    public function onFailure(ServerRequestInterface $request): ResponseInterface|null
    {
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
