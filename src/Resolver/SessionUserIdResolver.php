<?php

namespace Linkedcode\Middleware\Csrf\Resolver;

use Linkedcode\Middleware\Csrf\Contracts\UserIdResolver;
use Odan\Session\SessionInterface;
use Psr\Http\Message\ServerRequestInterface;

final class SessionUserIdResolver implements UserIdResolver
{
    public function __construct(private SessionInterface $session) {}

    public function resolve(ServerRequestInterface $request): ?string
    {
        return $this->session->get('user_id') ?? null;
    }
}
