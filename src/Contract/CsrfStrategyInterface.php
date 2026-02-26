<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Contract;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface CsrfStrategyInterface
{
    public function onSuccess(ServerRequestInterface $request): ServerRequestInterface;

    public function onFailure(ServerRequestInterface $request): ResponseInterface|null;
}
