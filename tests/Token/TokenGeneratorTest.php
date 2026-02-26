<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Tests\Token;

use Linkedcode\Middleware\Csrf\Storage\SessionTokenStorage;
use Linkedcode\Middleware\Csrf\Tests\Fixtures\InMemorySession;
use Linkedcode\Middleware\Csrf\Token\TokenGenerator;
use PHPUnit\Framework\TestCase;

final class TokenGeneratorTest extends TestCase
{
    private const SECRET = 'super-secret-key-that-is-at-least-32-chars-long!!';

    private TokenGenerator $generator;
    private SessionTokenStorage $storage;

    protected function setUp(): void
    {
        $session       = new InMemorySession();
        $this->storage = new SessionTokenStorage($session);
        $this->generator = new TokenGenerator($this->storage, self::SECRET);
    }

    public function testGenerateReturnsToken(): void
    {
        $token = $this->generator->generate();

        $this->assertNotEmpty($token->getId());
        $this->assertNotEmpty($token->getValue());
    }

    public function testGenerateStoresToken(): void
    {
        $token = $this->generator->generate();

        $this->assertTrue($this->storage->exists($token->getId()));
        $this->assertSame($token->getValue(), $this->storage->retrieve($token->getId()));
    }

    public function testEachCallProducesUniqueToken(): void
    {
        $token1 = $this->generator->generate();
        $token2 = $this->generator->generate();

        $this->assertNotSame($token1->getId(), $token2->getId());
        $this->assertNotSame($token1->getValue(), $token2->getValue());
    }

    public function testShortSecretThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TokenGenerator($this->storage, 'short');
    }

    public function testTokenValueIsUrlSafeBase64(): void
    {
        $token = $this->generator->generate();

        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_\-]+$/', $token->getValue());
    }
}
