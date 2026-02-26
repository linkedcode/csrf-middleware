<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Tests\Token;

use Linkedcode\Middleware\Csrf\Token\CsrfToken;
use PHPUnit\Framework\TestCase;

final class CsrfTokenTest extends TestCase
{
    public function testGetIdReturnsId(): void
    {
        $token = new CsrfToken('my-id', 'my-value');
        $this->assertSame('my-id', $token->getId());
    }

    public function testGetValueReturnsValue(): void
    {
        $token = new CsrfToken('my-id', 'my-value');
        $this->assertSame('my-value', $token->getValue());
    }

    public function testToStringReturnsValue(): void
    {
        $token = new CsrfToken('my-id', 'my-value');
        $this->assertSame('my-value', (string) $token);
    }
}
