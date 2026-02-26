<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Tests\Twig;

use Linkedcode\Middleware\Csrf\Storage\SessionTokenStorage;
use Linkedcode\Middleware\Csrf\Tests\Fixtures\InMemorySession;
use Linkedcode\Middleware\Csrf\Token\TokenGenerator;
use Linkedcode\Middleware\Csrf\Twig\CsrfExtension;
use PHPUnit\Framework\TestCase;
use Twig\TwigFunction;

final class CsrfExtensionTest extends TestCase
{
    private const SECRET = 'super-secret-key-that-is-at-least-32-chars-long!!';

    private CsrfExtension  $extension;
    private TokenGenerator $generator;

    protected function setUp(): void
    {
        $session         = new InMemorySession();
        $storage         = new SessionTokenStorage($session);
        $this->generator = new TokenGenerator($storage, self::SECRET);
        $this->extension = new CsrfExtension($this->generator);
    }

    // -------------------------------------------------------------------------
    // getFunctions
    // -------------------------------------------------------------------------

    public function testGetFunctionsReturnsTwigFunctions(): void
    {
        $functions = $this->extension->getFunctions();

        $this->assertCount(3, $functions);
        $this->assertContainsOnlyInstancesOf(TwigFunction::class, $functions);
    }

    public function testGetFunctionsRegistersExpectedNames(): void
    {
        $names = array_map(
            fn(TwigFunction $f) => $f->getName(),
            $this->extension->getFunctions()
        );

        $this->assertContains('csrf_token', $names);
        $this->assertContains('csrf_field', $names);
        $this->assertContains('csrf_meta', $names);
    }

    // -------------------------------------------------------------------------
    // token()
    // -------------------------------------------------------------------------

    public function testTokenReturnsNonEmptyString(): void
    {
        $this->assertNotEmpty($this->extension->token());
    }

    public function testTokenGeneratesNewTokenEachCall(): void
    {
        $first  = $this->extension->token();
        $second = $this->extension->token();

        $this->assertNotSame($first, $second);
    }

    // -------------------------------------------------------------------------
    // field()
    // -------------------------------------------------------------------------

    public function testFieldReturnsHiddenInput(): void
    {
        $html = $this->extension->field();

        $this->assertStringContainsString('<input type="hidden"', $html);
    }

    public function testFieldUsesDefaultInputName(): void
    {
        $html = $this->extension->field();

        $this->assertStringContainsString('name="_csrf_token"', $html);
    }

    public function testFieldUsesCustomInputName(): void
    {
        $html = $this->extension->field('my_token');

        $this->assertStringContainsString('name="my_token"', $html);
    }

    public function testFieldContainsTokenValue(): void
    {
        $html = $this->extension->field();

        $this->assertMatchesRegularExpression('/value="[^"]+"/', $html);
    }

    public function testFieldEscapesCustomInputName(): void
    {
        $html = $this->extension->field('<evil>');

        $this->assertStringNotContainsString('<evil>', $html);
        $this->assertStringContainsString('&lt;evil&gt;', $html);
    }

    // -------------------------------------------------------------------------
    // meta()
    // -------------------------------------------------------------------------

    public function testMetaReturnsMetaTag(): void
    {
        $html = $this->extension->meta();

        $this->assertStringContainsString('<meta', $html);
        $this->assertStringContainsString('content=', $html);
    }

    public function testMetaUsesDefaultMetaName(): void
    {
        $html = $this->extension->meta();

        $this->assertStringContainsString('name="csrf-token"', $html);
    }

    public function testMetaUsesCustomMetaName(): void
    {
        $html = $this->extension->meta('x-csrf');

        $this->assertStringContainsString('name="x-csrf"', $html);
    }

    public function testMetaContainsTokenValue(): void
    {
        $html = $this->extension->meta();

        $this->assertMatchesRegularExpression('/content="[^"]+"/', $html);
    }

    public function testMetaEscapesCustomMetaName(): void
    {
        $html = $this->extension->meta('<evil>');

        $this->assertStringNotContainsString('<evil>', $html);
        $this->assertStringContainsString('&lt;evil&gt;', $html);
    }
}
