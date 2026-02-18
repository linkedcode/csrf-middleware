<?php

namespace Linkedcode\Middleware\Csrf\Helper;

use Linkedcode\Middleware\Csrf\CsrfTokenManager;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;
use Psr\Http\Message\ServerRequestInterface;

final class CsrfTwigExtension extends AbstractExtension
{
    public function __construct(
        private CsrfTokenManager $tokenManager,
        private string $fieldName = '_csrf'
    ) {}

    public function getFunctions(): array
    {
        return [
            new TwigFunction('csrf_field', [$this, 'renderField'], ['is_safe' => ['html']]),
            new TwigFunction('csrf_token', [$this, 'getToken']),
        ];
    }

    public function renderField(ServerRequestInterface $request): string
    {
        $token = $this->tokenManager->generate($request);

        return sprintf(
            '<input type="hidden" name="%s" value="%s">',
            htmlspecialchars($this->fieldName, ENT_QUOTES, 'UTF-8'),
            htmlspecialchars($token, ENT_QUOTES, 'UTF-8')
        );
    }

    public function getToken(ServerRequestInterface $request): string
    {
        return $this->tokenManager->generate($request);
    }
}
