<?php

declare(strict_types=1);

namespace Linkedcode\Middleware\Csrf\Twig;

use Linkedcode\Middleware\Csrf\Token\TokenGenerator;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * Twig extension that exposes CSRF helpers to templates.
 *
 * Available functions:
 *   csrf_token()           → returns the raw token value string
 *   csrf_field()           → returns a complete <input type="hidden"> HTML element
 *   csrf_meta()            → returns a <meta name="csrf-token" content="..."> tag (for AJAX)
 */
final class CsrfExtension extends AbstractExtension
{
    private const INPUT_NAME = '_csrf_token';
    private const META_NAME  = 'csrf-token';

    public function __construct(private readonly TokenGenerator $generator) {}

    /** @return TwigFunction[] */
    public function getFunctions(): array
    {
        return [
            new TwigFunction(
                'csrf_token',
                $this->token(...),
                ['is_safe' => ['html']],
            ),
            new TwigFunction(
                'csrf_field',
                $this->field(...),
                ['is_safe' => ['html']],
            ),
            new TwigFunction(
                'csrf_meta',
                $this->meta(...),
                ['is_safe' => ['html']],
            ),
        ];
    }

    /**
     * Returns the plain token value.
     */
    public function token(): string
    {
        return $this->generator->generate()->getValue();
    }

    /**
     * Returns a hidden input element ready to be embedded in a <form>.
     */
    public function field(string $inputName = self::INPUT_NAME): string
    {
        $value = htmlspecialchars($this->token(), ENT_QUOTES | ENT_HTML5);
        $name  = htmlspecialchars($inputName, ENT_QUOTES | ENT_HTML5);

        return sprintf('<input type="hidden" name="%s" value="%s">', $name, $value);
    }

    /**
     * Returns a <meta> tag that JavaScript can read to inject the token in AJAX headers.
     */
    public function meta(string $metaName = self::META_NAME): string
    {
        $value = htmlspecialchars($this->token(), ENT_QUOTES | ENT_HTML5);
        $name  = htmlspecialchars($metaName, ENT_QUOTES | ENT_HTML5);

        return sprintf('<meta name="%s" content="%s">', $name, $value);
    }
}
