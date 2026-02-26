<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf;

use Linkedcode\Middleware\Csrf\Contract\CsrfStrategyInterface;
use Linkedcode\Middleware\Csrf\Exception\InvalidCsrfTokenException;
use Linkedcode\Middleware\Csrf\Token\CsrfToken;
use Linkedcode\Middleware\Csrf\Token\TokenGenerator;
use Linkedcode\Middleware\Csrf\Token\TokenValidator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class CsrfMiddleware implements MiddlewareInterface
{
    private const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS', 'TRACE'];
    private const BODY_FIELD   = '_csrf_token';
    private const HEADER_NAME  = 'X-CSRF-Token';

    public function __construct(
        private readonly TokenGenerator      $generator,
        private readonly TokenValidator      $validator,
        private readonly CsrfStrategyInterface $strategy,
    ) {}

    public function process(
        ServerRequestInterface  $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        if (in_array(strtoupper($request->getMethod()), self::SAFE_METHODS, true)) {
            return $handler->handle($request);
        }

        $token = $this->extractToken($request);

        if ($token === null) {
            return $this->strategy->onFailure($request);
        }

        try {
            $this->validator->validate($token);
        } catch (InvalidCsrfTokenException) {
            $failureResponse = $this->strategy->onFailure($request);

            if ($failureResponse !== null) {
                return $failureResponse; // API/Web con 403
            }

            return $handler->handle($request);
        }

        $request = $this->strategy->onSuccess($request);

        return $handler->handle($request);
    }

    public function generateToken(): CsrfToken
    {
        return $this->generator->generate();
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        $body = $request->getParsedBody();
        if (is_array($body) && isset($body[self::BODY_FIELD]) && is_string($body[self::BODY_FIELD])) {
            return $body[self::BODY_FIELD];
        }

        $headerLine = $request->getHeaderLine(self::HEADER_NAME);
        if ($headerLine !== '') {
            return $headerLine;
        }

        return null;
    }
}
