<?php

namespace Linkedcode\Middleware\Csrf;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class CsrfMiddleware implements MiddlewareInterface
{
    public function __construct(
        private CsrfTokenManager $manager
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {

        $method = strtoupper($request->getMethod());

        if (!in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'])) {
            return $handler->handle($request);
        }

        $token =
            $request->getParsedBody()['_csrf']
            ?? $request->getHeaderLine('X-CSRF-Token')
            ?? null;

        $isValid = $token && $this->manager->validate($request, $token);

        $request = $request->withAttribute('csrf_valid', $isValid);

        return $handler->handle($request);
    }
}
