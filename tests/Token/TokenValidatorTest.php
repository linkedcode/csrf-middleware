<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Tests\Token;

use Linkedcode\Middleware\Csrf\Exception\InvalidCsrfTokenException;
use Linkedcode\Middleware\Csrf\Storage\SessionTokenStorage;
use Linkedcode\Middleware\Csrf\Tests\Fixtures\InMemorySession;
use Linkedcode\Middleware\Csrf\Token\TokenGenerator;
use Linkedcode\Middleware\Csrf\Token\TokenValidator;
use PHPUnit\Framework\TestCase;

final class TokenValidatorTest extends TestCase
{
    private const SECRET = 'super-secret-key-that-is-at-least-32-chars-long!!';

    private TokenGenerator  $generator;
    private TokenValidator  $validator;
    private SessionTokenStorage $storage;

    protected function setUp(): void
    {
        $session         = new InMemorySession();
        $this->storage   = new SessionTokenStorage($session);
        $this->generator = new TokenGenerator($this->storage, self::SECRET);
        $this->validator = new TokenValidator($this->storage, $this->generator);
    }

    public function testValidTokenPassesValidation(): void
    {
        $token = $this->generator->generate();

        // Should not throw
        $this->validator->validate($token->getValue());
        $this->addToAssertionCount(1);
    }

    public function testTokenIsInvalidatedAfterSuccessfulValidation(): void
    {
        $token = $this->generator->generate();
        $this->validator->validate($token->getValue());

        // Second use must fail (single-use)
        $this->expectException(InvalidCsrfTokenException::class);
        $this->validator->validate($token->getValue());
    }

    public function testTamperedSignatureFailsValidation(): void
    {
        $token   = $this->generator->generate();
        $tampered = substr($token->getValue(), 0, -4) . 'XXXX';

        $this->expectException(InvalidCsrfTokenException::class);
        $this->validator->validate($tampered);
    }

    public function testInvalidBase64FailsValidation(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->validator->validate('!!!not-base64!!!');
    }

    public function testUnknownTokenIdFailsValidation(): void
    {
        // Generate a legitimately signed token from a different storage
        $otherSession  = new InMemorySession();
        $otherStorage  = new SessionTokenStorage($otherSession);
        $otherGen      = new TokenGenerator($otherStorage, self::SECRET);
        $foreignToken  = $otherGen->generate();

        $this->expectException(InvalidCsrfTokenException::class);
        $this->validator->validate($foreignToken->getValue());
    }

    public function testExpiredTokenFailsValidation(): void
    {
        $validator = new TokenValidator($this->storage, $this->generator, maxAge: -1);
        $token     = $this->generator->generate();

        $this->expectException(InvalidCsrfTokenException::class);
        $validator->validate($token->getValue());
    }

    public function testIsValidReturnsTrueForValidToken(): void
    {
        $token = $this->generator->generate();
        $this->assertTrue($this->validator->isValid($token->getValue()));
    }

    public function testIsValidReturnsFalseForInvalidToken(): void
    {
        $this->assertFalse($this->validator->isValid('garbage'));
    }
}
