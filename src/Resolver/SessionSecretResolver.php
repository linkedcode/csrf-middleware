<?php

namespace Linkedcode\Middleware\Csrf\Resolver;

use Linkedcode\Middleware\Csrf\Contracts\SecretResolver;
use Odan\Session\SessionInterface;
use Psr\Http\Message\ServerRequestInterface;

final class SessionSecretResolver implements SecretResolver
{
    public function __construct(private SessionInterface $session) {}

    public function resolve(ServerRequestInterface $request): string
    {
        return $this->session->get('csrf_secret');
    }
}
