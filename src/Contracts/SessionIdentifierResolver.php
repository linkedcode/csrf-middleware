<?php

namespace Linkedcode\Middleware\Csrf\Contracts;

use Psr\Http\Message\ServerRequestInterface;

interface SessionIdentifierResolver
{
    public function resolve(ServerRequestInterface $request): string;
}
