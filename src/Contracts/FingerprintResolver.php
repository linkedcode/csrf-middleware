<?php

namespace Linkedcode\Middleware\Csrf\Contracts;

use Psr\Http\Message\ServerRequestInterface;

interface FingerprintResolver
{
    public function resolve(ServerRequestInterface $request): string;
}
