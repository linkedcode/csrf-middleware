<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Tests\Strategy;

use Linkedcode\Middleware\Csrf\Strategy\CsrfFailMode;
use Linkedcode\Middleware\Csrf\Strategy\WebStrategy;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class WebStrategyTest extends TestCase
{
    private WebStrategy $strategy;

    protected function setUp(): void
    {
        $factory = new Psr17Factory();
        $this->strategy = new WebStrategy($factory, failMode: CsrfFailMode::Always);
    }

    public function testOnSuccessAddsAttribute(): void
    {
        $request = new ServerRequest('POST', '/');
        $result  = $this->strategy->onSuccess($request);

        $this->assertTrue($result->getAttribute(WebStrategy::ATTRIBUTE));
    }

    public function testOnSuccessDoesNotMutateOriginalRequest(): void
    {
        $request = new ServerRequest('POST', '/');
        $this->strategy->onSuccess($request);

        $this->assertNull($request->getAttribute(WebStrategy::ATTRIBUTE));
    }

    public function testOnFailureReturns403(): void
    {
        $request  = new ServerRequest('POST', '/');
        $response = $this->strategy->onFailure($request);

        $this->assertSame(403, $response->getStatusCode());
    }

    public function testOnFailureReturnsHtmlContentType(): void
    {
        $request  = new ServerRequest('POST', '/');
        $response = $this->strategy->onFailure($request);

        $this->assertStringContainsString('text/html', $response->getHeaderLine('Content-Type'));
    }

    public function testOnFailureBodyContainsMessage(): void
    {
        $factory  = new Psr17Factory();
        $strategy = new WebStrategy($factory, 'Custom error message', failMode: CsrfFailMode::Always);
        $request  = new ServerRequest('POST', '/');
        $response = $strategy->onFailure($request);

        $this->assertStringContainsString('Custom error message', (string) $response->getBody());
    }

    public function testOnFailureReturnsNullWhenFailFastIsFalse(): void
    {
        $factory  = new Psr17Factory();
        $strategy = new WebStrategy($factory);
        $request  = new ServerRequest('POST', '/');

        $this->assertNull($strategy->onFailure($request));
    }

    public function testUnauthenticatedOnlyReturns403WhenAuthAttributeMissing(): void
    {
        $factory  = new Psr17Factory();
        $strategy = new WebStrategy(
            $factory,
            failMode: CsrfFailMode::UnauthenticatedOnly,
            onAuthenticatedFailure: fn () => $factory->createResponse(302)->withHeader('Location', '/dashboard'),
        );
        $request = new ServerRequest('POST', '/');

        $response = $strategy->onFailure($request);

        $this->assertSame(403, $response->getStatusCode());
    }

    public function testUnauthenticatedOnlyDelegatesToCallbackWhenAuthAttributePresent(): void
    {
        $factory  = new Psr17Factory();
        $strategy = new WebStrategy(
            $factory,
            failMode: CsrfFailMode::UnauthenticatedOnly,
            authRequestAttribute: 'user_id',
            onAuthenticatedFailure: fn () => $factory->createResponse(302)->withHeader('Location', '/dashboard'),
        );
        $request = (new ServerRequest('POST', '/'))->withAttribute('user_id', 42);

        $response = $strategy->onFailure($request);

        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('/dashboard', $response->getHeaderLine('Location'));
    }

    public function testUnauthenticatedOnlyFallsBackTo403WhenCallbackReturnsNull(): void
    {
        $factory  = new Psr17Factory();
        $strategy = new WebStrategy(
            $factory,
            failMode: CsrfFailMode::UnauthenticatedOnly,
            onAuthenticatedFailure: fn () => null,
        );
        $request = (new ServerRequest('POST', '/'))->withAttribute('user_id', 42);

        $response = $strategy->onFailure($request);

        $this->assertSame(403, $response->getStatusCode());
    }

    public function testRenderFailureOverridesDefaultResponse(): void
    {
        $factory  = new Psr17Factory();
        $strategy = new WebStrategy(
            $factory,
            failMode: CsrfFailMode::Always,
            renderFailure: fn ($request, $message) => $factory->createResponse(419)
                ->withHeader('Content-Type', 'text/html')
                ->withBody(\Nyholm\Psr7\Stream::create("Custom page: {$message}")),
        );
        $request = new ServerRequest('POST', '/');

        $response = $strategy->onFailure($request);

        $this->assertSame(419, $response->getStatusCode());
        $this->assertStringContainsString('Custom page:', (string) $response->getBody());
    }
}
