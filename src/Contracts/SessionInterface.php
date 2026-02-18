<?php

namespace Linkedcode\Middleware\Csrf\Contracts;

interface SessionInterface
{
    public function get(string $key, mixed $default = null): mixed;

    public function set(string $key, mixed $value): void;

    public function remove(string $key): void;
}
