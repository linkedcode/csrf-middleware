<?php

use Linkedcode\Middleware\Csrf\Contracts\FingerprintResolver as FingerprintResolverInterface;
use Psr\Http\Message\ServerRequestInterface;

final class FingerprintResolver implements FingerprintResolverInterface
{
    public function resolve(ServerRequestInterface $request): string
    {
        $ua = $request->getHeaderLine('User-Agent');

        return substr(
            hash('sha256', $ua),
            0,
            16
        );
    }
}
