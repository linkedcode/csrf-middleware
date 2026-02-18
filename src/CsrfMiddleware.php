<?php

namespace Linkedcode\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Odan\Session\SessionInterface;

class CsrfMiddleware implements MiddlewareInterface
{
    private SessionInterface $session;
    private string $keyName = 'csrf_name';
    private string $keyValue = 'csrf_value';

    public function __construct(
        SessionInterface $session
    ) {
        $this->session = $session;
    }

    public function process(Request $request, RequestHandler $handler): Response
    {
        if (!$this->session->has($this->keyName)) {
            $this->session->set($this->keyName, 'csrf_token_' . bin2hex(random_bytes(8)));
        }

        if (!$this->session->has($this->keyValue)) {
            $this->session->set($this->keyValue, bin2hex(random_bytes(32)));
        }

        if (in_array($request->getMethod(), ['POST', 'PUT', 'DELETE', 'PATCH'])) {
            $name = $request->getParsedBody()[$this->session->get($this->keyName)] ?? '';
            $value = $request->getParsedBody()[$this->keyValue] ?? '';
            $valid = hash_equals($this->session->get($this->keyValue), $value);

            $request = $request->withAttribute("csrf_status", $valid);
        }

        $request = $request->withAttribute($this->keyName, $this->session->get($this->keyName));
        $request = $request->withAttribute($this->keyValue, $this->session->get($this->keyValue));

        return $handler->handle($request);
    }
}
