<?php

namespace Linkedcode\Middleware\Csrf\Contracts;

use Psr\Http\Message\ServerRequestInterface;

interface UserIdResolver
{
    public function resolve(ServerRequestInterface $request): ?string;
}
