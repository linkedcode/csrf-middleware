<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Tests\Middleware;

use Linkedcode\Middleware\Csrf\CsrfMiddleware;
use Linkedcode\Middleware\Csrf\Storage\SessionTokenStorage;
use Linkedcode\Middleware\Csrf\Strategy\ApiStrategy;
use Linkedcode\Middleware\Csrf\Strategy\WebStrategy;
use Linkedcode\Middleware\Csrf\Tests\Fixtures\InMemorySession;
use Linkedcode\Middleware\Csrf\Token\TokenGenerator;
use Linkedcode\Middleware\Csrf\Token\TokenValidator;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class CsrfMiddlewareTest extends TestCase
{
    private const SECRET = 'super-secret-key-that-is-at-least-32-chars-long!!';

    private Psr17Factory    $factory;
    private TokenGenerator  $generator;
    private TokenValidator  $validator;
    private SessionTokenStorage $storage;

    protected function setUp(): void
    {
        $this->factory   = new Psr17Factory();
        $session         = new InMemorySession();
        $this->storage   = new SessionTokenStorage($session);
        $this->generator = new TokenGenerator($this->storage, self::SECRET);
        $this->validator = new TokenValidator($this->storage, $this->generator);
    }

    // -------------------------------------------------------------------------
    // Safe methods
    // -------------------------------------------------------------------------

    /** @dataProvider safeMethods */
    public function testSafeMethodsPassThrough(string $method): void
    {
        $middleware = $this->buildWebMiddleware();
        $request    = new ServerRequest($method, '/');
        $handler    = $this->buildOkHandler();

        $response = $middleware->process($request, $handler);
        $this->assertSame(200, $response->getStatusCode());
    }

    /** @return array<string, array{string}> */
    public static function safeMethods(): array
    {
        return [
            'GET'     => ['GET'],
            'HEAD'    => ['HEAD'],
            'OPTIONS' => ['OPTIONS'],
            'TRACE'   => ['TRACE'],
        ];
    }

    // -------------------------------------------------------------------------
    // Web strategy
    // -------------------------------------------------------------------------

    public function testWebValidTokenInPostBodyPasses(): void
    {
        $middleware = $this->buildWebMiddleware();
        $token      = $this->generator->generate();

        $request = (new ServerRequest('POST', '/'))
            ->withParsedBody(['_csrf_token' => $token->getValue()]);

        $handler  = $this->buildOkHandler();
        $response = $middleware->process($request, $handler);

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testWebMissingTokenReturns403(): void
    {
        $middleware = $this->buildWebMiddleware();
        $request    = new ServerRequest('POST', '/');
        $handler    = $this->buildOkHandler();
        $response   = $middleware->process($request, $handler);

        $this->assertSame(403, $response->getStatusCode());
        $this->assertStringContainsString('text/html', $response->getHeaderLine('Content-Type'));
    }

    public function testWebTamperedTokenReturns403(): void
    {
        $middleware = $this->buildWebMiddleware();
        $token      = $this->generator->generate();

        $request = (new ServerRequest('POST', '/'))
            ->withParsedBody(['_csrf_token' => $token->getValue() . 'tampered']);

        $response = $middleware->process($request, $this->buildOkHandler());
        $this->assertSame(403, $response->getStatusCode());
    }

    public function testWebTokenIsSingleUse(): void
    {
        $middleware = $this->buildWebMiddleware();
        $token      = $this->generator->generate();

        $makeRequest = fn() => (new ServerRequest('POST', '/'))
            ->withParsedBody(['_csrf_token' => $token->getValue()]);

        // First use: passes
        $response = $middleware->process($makeRequest(), $this->buildOkHandler());
        $this->assertSame(200, $response->getStatusCode());

        // Second use: rejected
        $response = $middleware->process($makeRequest(), $this->buildOkHandler());
        $this->assertSame(403, $response->getStatusCode());
    }

    public function testWebValidTokenSetsAttribute(): void
    {
        $capturedRequest = null;
        $middleware      = $this->buildWebMiddleware();
        $token           = $this->generator->generate();

        $request = (new ServerRequest('POST', '/'))
            ->withParsedBody(['_csrf_token' => $token->getValue()]);

        $handler = new class($capturedRequest) implements RequestHandlerInterface {
            public function __construct(private ?ServerRequestInterface &$captured) {}
            public function handle(ServerRequestInterface $r): ResponseInterface {
                $this->captured = $r;
                return (new Psr17Factory())->createResponse(200);
            }
        };

        $middleware->process($request, $handler);
        $this->assertTrue($capturedRequest?->getAttribute(WebStrategy::ATTRIBUTE));
    }

    // -------------------------------------------------------------------------
    // API strategy
    // -------------------------------------------------------------------------

    public function testApiValidTokenInHeaderPasses(): void
    {
        $middleware = $this->buildApiMiddleware();
        $token      = $this->generator->generate();

        $request = (new ServerRequest('POST', '/api/resource'))
            ->withHeader('X-CSRF-Token', $token->getValue());

        $response = $middleware->process($request, $this->buildOkHandler());
        $this->assertSame(200, $response->getStatusCode());
    }

    public function testApiMissingTokenReturnsJsonError(): void
    {
        $middleware = $this->buildApiMiddleware();
        $request    = new ServerRequest('POST', '/api/resource');
        $response   = $middleware->process($request, $this->buildOkHandler());

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));

        $body = json_decode((string) $response->getBody(), true);
        $this->assertSame('forbidden', $body['error']);
    }

    public function testApiTokenIsSingleUse(): void
    {
        $middleware = $this->buildApiMiddleware();
        $token      = $this->generator->generate();

        $makeRequest = fn() => (new ServerRequest('POST', '/api/resource'))
            ->withHeader('X-CSRF-Token', $token->getValue());

        $response = $middleware->process($makeRequest(), $this->buildOkHandler());
        $this->assertSame(200, $response->getStatusCode());

        $response = $middleware->process($makeRequest(), $this->buildOkHandler());
        $this->assertSame(403, $response->getStatusCode());
    }

    public function testTokenCanBeGeneratedFromMiddleware(): void
    {
        $middleware = $this->buildWebMiddleware();
        $token      = $middleware->generateToken();

        $this->assertNotEmpty($token->getId());
        $this->assertNotEmpty($token->getValue());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function buildWebMiddleware(): CsrfMiddleware
    {
        return new CsrfMiddleware(
            $this->generator,
            $this->validator,
            new WebStrategy($this->factory, failFast: true),
        );
    }

    private function buildApiMiddleware(): CsrfMiddleware
    {
        return new CsrfMiddleware(
            $this->generator,
            $this->validator,
            new ApiStrategy($this->factory),
        );
    }

    private function buildOkHandler(): RequestHandlerInterface
    {
        return new class($this->factory) implements RequestHandlerInterface {
            public function __construct(private Psr17Factory $factory) {}
            public function handle(ServerRequestInterface $r): ResponseInterface {
                return $this->factory->createResponse(200);
            }
        };
    }
}
