<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Tests\Strategy;

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
        $this->strategy = new WebStrategy($factory, failFast: true);
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
        $strategy = new WebStrategy($factory, 'Custom error message', failFast: true);
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
}
