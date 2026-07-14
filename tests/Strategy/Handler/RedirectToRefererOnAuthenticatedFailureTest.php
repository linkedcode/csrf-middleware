<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Tests\Strategy\Handler;

use Linkedcode\Middleware\Csrf\Contract\CsrfFailureNotifierInterface;
use Linkedcode\Middleware\Csrf\Strategy\Handler\RedirectToRefererOnAuthenticatedFailure;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class RedirectToRefererOnAuthenticatedFailureTest extends TestCase
{
    public function testRedirectsToReferer(): void
    {
        $factory = new Psr17Factory();
        $handler = new RedirectToRefererOnAuthenticatedFailure($factory, null);
        $request = (new ServerRequest('POST', '/account/edit'))
            ->withHeader('Referer', '/account/edit');

        $response = $handler($request);

        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('/account/edit', $response->getHeaderLine('Location'));
    }

    public function testFallsBackToFallbackPathWithoutReferer(): void
    {
        $factory = new Psr17Factory();
        $handler = new RedirectToRefererOnAuthenticatedFailure($factory, null, fallbackPath: '/dashboard');
        $request = new ServerRequest('POST', '/account/edit');

        $response = $handler($request);

        $this->assertSame('/dashboard', $response->getHeaderLine('Location'));
    }

    public function testNotifiesWithGivenMessage(): void
    {
        $factory  = new Psr17Factory();
        $notifier = new class implements CsrfFailureNotifierInterface {
            public ?string $received = null;

            public function notify(ServerRequestInterface $request, string $message): void
            {
                $this->received = $message;
            }
        };

        $handler = new RedirectToRefererOnAuthenticatedFailure($factory, $notifier, 'Custom message');
        $request = new ServerRequest('POST', '/account/edit');

        $handler($request);

        $this->assertSame('Custom message', $notifier->received);
    }
}
