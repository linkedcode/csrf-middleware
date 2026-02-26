<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Tests\Storage;

use Linkedcode\Middleware\Csrf\Storage\SessionTokenStorage;
use Linkedcode\Middleware\Csrf\Tests\Fixtures\InMemorySession;
use PHPUnit\Framework\TestCase;

final class SessionTokenStorageTest extends TestCase
{
    private SessionTokenStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new SessionTokenStorage(new InMemorySession());
    }

    public function testStoreAndRetrieve(): void
    {
        $this->storage->store('abc', 'token-value');
        $this->assertSame('token-value', $this->storage->retrieve('abc'));
    }

    public function testRetrieveReturnsNullForUnknownId(): void
    {
        $this->assertNull($this->storage->retrieve('unknown'));
    }

    public function testExistsReturnsTrueAfterStore(): void
    {
        $this->storage->store('abc', 'token-value');
        $this->assertTrue($this->storage->exists('abc'));
    }

    public function testExistsReturnsFalseBeforeStore(): void
    {
        $this->assertFalse($this->storage->exists('abc'));
    }

    public function testInvalidateRemovesToken(): void
    {
        $this->storage->store('abc', 'token-value');
        $this->storage->invalidate('abc');

        $this->assertFalse($this->storage->exists('abc'));
        $this->assertNull($this->storage->retrieve('abc'));
    }

    public function testMultipleTokensCanBeStored(): void
    {
        $this->storage->store('id1', 'value1');
        $this->storage->store('id2', 'value2');

        $this->assertSame('value1', $this->storage->retrieve('id1'));
        $this->assertSame('value2', $this->storage->retrieve('id2'));
    }

    public function testInvalidatingOneDoesNotAffectOthers(): void
    {
        $this->storage->store('id1', 'value1');
        $this->storage->store('id2', 'value2');
        $this->storage->invalidate('id1');

        $this->assertFalse($this->storage->exists('id1'));
        $this->assertTrue($this->storage->exists('id2'));
    }
}
