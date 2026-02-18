<?php

use Linkedcode\Middleware\Csrf\CsrfTokenManager;

/**
 * {{ csrf_input()|raw }}
 */
function csrf_input(CsrfTokenManager $manager, $request): string
{
    $token = $manager->generate($request);

    return sprintf(
        '<input type="hidden" name="_csrf" value="%s">',
        htmlspecialchars($token, ENT_QUOTES)
    );
}
