<?php

namespace Linkedcode\Middleware\Csrf\Resolver;

use Linkedcode\Middleware\Csrf\Contracts\SecretResolver;
use Linkedcode\Middleware\Csrf\Contracts\SessionIdentifierResolver;
use Psr\Http\Message\ServerRequestInterface;

final class DerivedSecretResolver implements SecretResolver
{
    public function __construct(
        private string $serverKey,
        private SessionIdentifierResolver $sessionResolver
    ) {}

    public function resolve(ServerRequestInterface $request): string
    {
        $sessionId = $this->sessionResolver->resolve($request);

        return hash_hmac(
            'sha256',
            $sessionId,
            $this->serverKey,
            true
        );
    }
}
