<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Thecyrilcril\Impersonate\Impersonate;

it('registers the impersonation blade directives', function (): void {
    $directives = Blade::getCustomDirectives();

    expect($directives)
        ->toHaveKeys([
            'impersonating', 'endImpersonating',
            'canImpersonate', 'endCanImpersonate',
            'canBeImpersonated', 'endCanBeImpersonated',
        ]);
});

it('renders the impersonating directive based on session state', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();

    $template = '@impersonating yes @endImpersonating';

    expect(trim(Blade::render($template)))->toBe('');

    Auth::guard('web')->login($admin);
    app(Impersonate::class)->take($admin, $target);

    expect(Blade::render($template))->toContain('yes');
});

it('renders the impersonating directive scoped to a guard', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();

    Auth::guard('web')->login($admin);
    app(Impersonate::class)->take($admin, $target, 'web');

    expect(Blade::render("@impersonating('web') yes @endImpersonating"))->toContain('yes')
        ->and(trim(Blade::render("@impersonating('admin') yes @endImpersonating")))->toBe('');
});

it('renders the canImpersonate directive from the authenticated user', function (): void {
    $allowed = $this->makeUser(['may_impersonate' => true]);

    Auth::guard('web')->login($allowed);

    expect(Blade::render('@canImpersonate yes @endCanImpersonate'))->toContain('yes');

    $denied = $this->makeUser(['may_impersonate' => false]);
    Auth::guard('web')->login($denied);

    expect(trim(Blade::render('@canImpersonate yes @endCanImpersonate')))->toBe('');
});

it('renders the canBeImpersonated directive for a given user', function (): void {
    $normal = $this->makeUser(['protected' => false]);
    $protected = $this->makeUser(['protected' => true]);

    expect(Blade::render('@canBeImpersonated($user) yes @endCanBeImpersonated', ['user' => $normal]))
        ->toContain('yes')
        ->and(trim(Blade::render('@canBeImpersonated($user) yes @endCanBeImpersonated', ['user' => $protected])))
        ->toBe('');
});
