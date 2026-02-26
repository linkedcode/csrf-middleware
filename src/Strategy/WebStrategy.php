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
 * On failure : returns an HTTP 403 response with a plain-text or HTML body.
 */
final class WebStrategy implements CsrfStrategyInterface
{
    public const ATTRIBUTE = 'csrf_valid';

    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly string $failureMessage = 'CSRF token validation failed.',
        private readonly bool $failFast = false
    ) {}

    public function onSuccess(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(self::ATTRIBUTE, true);
    }

    public function onFailure(ServerRequestInterface $request): ResponseInterface|null
    {
        if (!$this->failFast) {
            return null;
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
