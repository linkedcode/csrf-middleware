<?php

namespace App\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Odan\Session\SessionInterface;
use Psr\Http\Message\ResponseFactoryInterface;

class CsrfMiddleware implements MiddlewareInterface
{
    private SessionInterface $session;
    private ResponseFactoryInterface $responseFactory;
    private string $keyName = 'csrf_name';
    private string $keyValue = 'csrf_value';

    public function __construct(
        SessionInterface $session,
        ResponseFactoryInterface $responseFactory
    ) {
        $this->session = $session;
        $this->responseFactory = $responseFactory;
    }

    public function process(Request $request, RequestHandler $handler): Response
    {
        // Generar nombre y valor del token si no existen
        if (!$this->session->has($this->keyName)) {
            $this->session->set($this->keyName, 'csrf_token_' . bin2hex(random_bytes(8)));
        }
        if (!$this->session->has($this->keyValue)) {
            $this->session->set($this->keyValue, bin2hex(random_bytes(32)));
        }

        // Validar en métodos POST, PUT, DELETE, etc.
        if (in_array($request->getMethod(), ['POST', 'PUT', 'DELETE', 'PATCH'])) {
            $name = $request->getParsedBody()[$this->session->get($this->keyName)] ?? '';
            $value = $request->getParsedBody()[$this->keyValue] ?? '';
            if (!hash_equals($this->session->get($this->keyValue), $value)) {
                $response = $this->responseFactory->createResponse(400);
                $response->getBody()->write('CSRF token validation failed.');
                return $response;
            }
        }

        // Agregar los datos del token a los atributos de la solicitud
        $request = $request->withAttribute($this->keyName, $this->session->get($this->keyName));
        $request = $request->withAttribute($this->keyValue, $this->session->get($this->keyValue));

        return $handler->handle($request);
    }
}
