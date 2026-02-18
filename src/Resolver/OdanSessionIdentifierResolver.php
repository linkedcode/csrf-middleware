<?php

namespace Linkedcode\Middleware\Csrf\Resolver;

use Linkedcode\Middleware\Csrf\Contracts\SessionIdentifierResolver;
use Odan\Session\SessionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class OdanSessionIdentifierResolver implements SessionIdentifierResolver
{
    public function __construct(private SessionManagerInterface $session) {}

    public function resolve(ServerRequestInterface $request): string
    {
        return $this->session->getId();
    }
}
