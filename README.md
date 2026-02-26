# linkedcode/csrf-middleware

Middleware PSR-15 para protección CSRF con tokens firmados de un solo uso, estrategias Web/API y extensión Twig.

## Requisitos

- PHP >= 8.1
- `psr/http-message` ^1.1 | ^2.0
- `psr/http-server-middleware` ^1.0
- `twig/twig` ^3.0

## Instalación

```bash
composer require linkedcode/csrf-middleware
```

## Funcionamiento

El middleware intercepta todas las peticiones con métodos **no seguros** (`POST`, `PUT`, `DELETE`, `PATCH`, etc.) y exige un token CSRF válido. Las peticiones con métodos seguros (`GET`, `HEAD`, `OPTIONS`, `TRACE`) se dejan pasar sin validación.

### Formato del token

El token es un payload codificado en base64url con la estructura:

```
base64url( id | timestamp | hmac(id|timestamp, secret) )
```

- **`id`**: identificador aleatorio de 16 bytes almacenado en sesión.
- **`timestamp`**: momento de generación, usado para verificar expiración.
- **`hmac`**: firma HMAC-SHA256 que garantiza integridad.

### Flujo de validación

1. Se extrae el token del cuerpo de la petición (`_csrf_token`) o de la cabecera (`X-CSRF-Token`).
2. Se decodifica y verifica la estructura del payload.
3. Se comprueba que el `id` exista en el almacenamiento (tokens ya usados son rechazados).
4. Se verifica que el valor almacenado coincida con el recibido.
5. Se valida la firma HMAC.
6. Se comprueba que el token no haya expirado (TTL configurable, por defecto 3600 s).
7. El token se invalida inmediatamente tras una validación exitosa (uso único).

## Configuración

### Instanciación básica

```php
use Linkedcode\Middleware\Csrf\CsrfMiddleware;
use Linkedcode\Middleware\Csrf\Storage\SessionTokenStorage;
use Linkedcode\Middleware\Csrf\Token\TokenGenerator;
use Linkedcode\Middleware\Csrf\Token\TokenValidator;
use Linkedcode\Middleware\Csrf\Strategy\WebStrategy;

$storage   = new SessionTokenStorage($session);        // $session implementa SessionInterface
$generator = new TokenGenerator($storage, 'tu-secreto-de-al-menos-32-caracteres');
$validator = new TokenValidator($storage, $generator); // TTL por defecto: 3600 s
$strategy  = new WebStrategy($responseFactory);

$middleware = new CsrfMiddleware($generator, $validator, $strategy);
```

### Parámetros de `TokenGenerator`

| Parámetro | Tipo     | Descripción                                               |
|-----------|----------|-----------------------------------------------------------|
| `$storage`| `CsrfTokenStorageInterface` | Almacenamiento de tokens.          |
| `$secret` | `string` | Clave secreta (mínimo 32 caracteres).                     |
| `$algo`   | `string` | Algoritmo HMAC (por defecto `sha256`).                    |

### Parámetros de `TokenValidator`

| Parámetro | Tipo  | Descripción                                              |
|-----------|-------|----------------------------------------------------------|
| `$maxAge` | `int` | Tiempo de vida del token en segundos (por defecto 3600). |

## Estrategias de respuesta

### `WebStrategy` (formularios HTML)

Devuelve una respuesta HTTP 403 con cuerpo HTML cuando falla la validación.

```php
use Linkedcode\Middleware\Csrf\Strategy\WebStrategy;

$strategy = new WebStrategy(
    responseFactory: $responseFactory,
    failureMessage:  'Token CSRF inválido.',  // mensaje mostrado al usuario
    failFast:        true,                    // false: deja pasar la petición sin el atributo csrf_valid
);
```

Con `failFast: false`, la petición llega al handler sin el atributo `csrf_valid`, lo que permite que el propio handler decida cómo manejar el error.

### `ApiStrategy` (AJAX / JSON)

Siempre devuelve una respuesta HTTP 403 con cuerpo JSON al fallar la validación.

```php
use Linkedcode\Middleware\Csrf\Strategy\ApiStrategy;

$strategy = new ApiStrategy(
    responseFactory: $responseFactory,
    failureMessage:  'CSRF token validation failed.',
);
```

Respuesta de error:

```json
{
  "error": "forbidden",
  "message": "CSRF token validation failed.",
  "code": 403
}
```

## Almacenamiento

La implementación incluida, `SessionTokenStorage`, guarda los tokens en sesión bajo la clave `_csrf_tokens` usando la abstracción `SessionInterface`, sin depender directamente de `$_SESSION`.

Para usar un backend distinto (Redis, base de datos, etc.), implementa `CsrfTokenStorageInterface`:

```php
use Linkedcode\Middleware\Csrf\Contract\CsrfTokenStorageInterface;

final class RedisTokenStorage implements CsrfTokenStorageInterface
{
    public function store(string $tokenId, string $tokenValue): void { /* ... */ }
    public function retrieve(string $tokenId): ?string              { /* ... */ }
    public function invalidate(string $tokenId): void               { /* ... */ }
    public function exists(string $tokenId): bool                   { /* ... */ }
}
```

## Integración con Twig

Registra la extensión en tu entorno Twig:

```php
use Linkedcode\Middleware\Csrf\Twig\CsrfExtension;

$twig->addExtension(new CsrfExtension($generator));
```

Funciones disponibles en plantillas:

| Función          | Descripción                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `csrf_token()`   | Devuelve el valor del token como cadena.                                    |
| `csrf_field()`   | Devuelve `<input type="hidden" name="_csrf_token" value="...">`.            |
| `csrf_meta()`    | Devuelve `<meta name="csrf-token" content="...">` para peticiones AJAX.    |

### Formulario HTML

```twig
<form method="post" action="/perfil">
    {{ csrf_field() }}
    <button type="submit">Guardar</button>
</form>
```

### AJAX / fetch

```twig
{{ csrf_meta() }}
```

```js
const token = document.querySelector('meta[name="csrf-token"]').content;

fetch('/api/recurso', {
    method: 'POST',
    headers: { 'X-CSRF-Token': token },
    body: JSON.stringify(data),
});
```

## Envío del token

El token puede enviarse de dos formas:

- **Cuerpo de la petición**: campo `_csrf_token` (formularios HTML).
- **Cabecera HTTP**: `X-CSRF-Token` (peticiones AJAX/API).

## Excepciones

`InvalidCsrfTokenException` se lanza internamente cuando:

- El token no tiene formato base64url válido.
- La estructura del payload es incorrecta.
- El token no existe en el almacenamiento (ya fue usado o nunca existió).
- El valor enviado no coincide con el almacenado.
- La firma HMAC no es válida.
- El token ha expirado.

## Licencia

GNU General Public License v3.0 — consulta el archivo [LICENSE](LICENSE) para más detalles.
