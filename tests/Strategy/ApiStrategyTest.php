<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Tests\Strategy;

use Linkedcode\Middleware\Csrf\Strategy\ApiStrategy;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class ApiStrategyTest extends TestCase
{
    private ApiStrategy $strategy;

    protected function setUp(): void
    {
        $factory = new Psr17Factory();
        $this->strategy = new ApiStrategy($factory);
    }

    public function testOnSuccessAddsAttribute(): void
    {
        $request = new ServerRequest('POST', '/api/resource');
        $result  = $this->strategy->onSuccess($request);

        $this->assertTrue($result->getAttribute(ApiStrategy::ATTRIBUTE));
    }

    public function testOnFailureReturns403(): void
    {
        $request  = new ServerRequest('POST', '/api/resource');
        $response = $this->strategy->onFailure($request);

        $this->assertSame(403, $response->getStatusCode());
    }

    public function testOnFailureReturnsJsonContentType(): void
    {
        $request  = new ServerRequest('POST', '/api/resource');
        $response = $this->strategy->onFailure($request);

        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
    }

    public function testOnFailureBodyIsValidJson(): void
    {
        $request  = new ServerRequest('POST', '/api/resource');
        $response = $this->strategy->onFailure($request);
        $body     = json_decode((string) $response->getBody(), true);

        $this->assertIsArray($body);
        $this->assertSame('forbidden', $body['error']);
        $this->assertSame(403, $body['code']);
    }

    public function testOnFailureBodyContainsCustomMessage(): void
    {
        $factory  = new Psr17Factory();
        $strategy = new ApiStrategy($factory, 'Token expired');
        $request  = new ServerRequest('POST', '/api/resource');
        $response = $strategy->onFailure($request);
        $body     = json_decode((string) $response->getBody(), true);

        $this->assertSame('Token expired', $body['message']);
    }
}
