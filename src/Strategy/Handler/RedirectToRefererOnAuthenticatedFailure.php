<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Strategy\Handler;

use Linkedcode\Middleware\Csrf\Contract\CsrfFailureNotifierInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Reusable onAuthenticatedFailure handler for WebStrategy: sends the given
 * message through the notifier (e.g. a session flash) and redirects back to
 * where the stale form was submitted from (the Referer header), falling back
 * to $fallbackPath when there is no Referer.
 */
final class RedirectToRefererOnAuthenticatedFailure
{
    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly ?CsrfFailureNotifierInterface $notifier,
        private readonly string $message = 'Tu sesión seguía activa, pero el formulario había quedado desactualizado. Probá de nuevo.',
        private readonly string $fallbackPath = '/',
    ) {
    }

    public function __invoke(ServerRequestInterface $request): ResponseInterface
    {
        $this->notifier?->notify($request, $this->message);

        $referer = $request->getHeaderLine('Referer');
        $location = $referer !== '' ? $referer : $this->fallbackPath;

        return $this->responseFactory->createResponse(302)
            ->withHeader('Location', $location);
    }
}
