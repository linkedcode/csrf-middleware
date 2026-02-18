<?php

namespace Linkedcode\Middleware\Csrf\Helper;

use Linkedcode\Middleware\Csrf\CsrfTokenManager;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Views\Twig;
use Twig\TwigFunction;

final class TwigCsrfMiddleware implements MiddlewareInterface
{
    public function __construct(
        private CsrfTokenManager $manager
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {

        $twig = Twig::fromRequest($request);
        $manager = $this->manager;

        $func = new TwigFunction('csrf_field', function (string $method = "POST") use ($manager, $request) {
            return sprintf(
                '<input type="hidden" name="_csrf" value="%s">',
                $manager->generate($request, $method)
            );
        }, ['is_safe' => ['html']]);

        $twig->getEnvironment()->addFunction($func);

        return $handler->handle($request);
    }
}
