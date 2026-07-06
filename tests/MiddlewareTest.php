<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Thecyrilcril\Impersonate\Http\Middleware\ProtectFromImpersonation;
use Thecyrilcril\Impersonate\Impersonate;

it('aborts with 403 while impersonating', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);
    app(Impersonate::class)->take($admin, $target);

    $middleware = app(ProtectFromImpersonation::class);

    $middleware->handle(Request::create('/settings/password'), static fn (): Response => new Response('ok'));
})->throws(HttpException::class);

it('passes the request through when not impersonating', function (): void {
    $middleware = app(ProtectFromImpersonation::class);

    $response = $middleware->handle(
        Request::create('/settings/password'),
        static fn (): Response => new Response('ok'),
    );

    expect($response->getContent())->toBe('ok');
});

it('registers the middleware alias', function (): void {
    $router = app('router');

    expect($router->getMiddleware())
        ->toHaveKey('impersonate.protect', ProtectFromImpersonation::class);
});
