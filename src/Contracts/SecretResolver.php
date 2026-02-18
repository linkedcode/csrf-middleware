<?php

namespace Linkedcode\Middleware\Csrf\Contracts;

use Psr\Http\Message\ServerRequestInterface;

interface SecretResolver
{
    public function resolve(ServerRequestInterface $request): string;
}
