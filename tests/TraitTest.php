<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Thecyrilcril\Impersonate\Impersonate;

it('impersonates through the trait helper', function (): void {
    $admin = $this->makeUser(['may_impersonate' => true]);
    $target = $this->makeUser();

    Auth::guard('web')->login($admin);

    expect($admin->impersonate($target))->toBeTrue()
        ->and($admin->isImpersonated())->toBeFalse()
        ->and($target->isImpersonated())->toBeTrue()
        ->and(Auth::guard('web')->id())->toBe($target->id);
});

it('leaves impersonation through the trait helper', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();

    Auth::guard('web')->login($admin);
    $admin->impersonate($target);

    expect($target->leaveImpersonation())->toBeTrue()
        ->and(Auth::guard('web')->id())->toBe($admin->id);
});

it('refuses to impersonate when the impersonator cannot impersonate', function (): void {
    $admin = $this->makeUser(['may_impersonate' => false]);
    $target = $this->makeUser();

    Auth::guard('web')->login($admin);

    expect($admin->impersonate($target))->toBeFalse()
        ->and(app(Impersonate::class)->isImpersonating())->toBeFalse();
});

it('refuses to impersonate a protected target', function (): void {
    $admin = $this->makeUser(['may_impersonate' => true]);
    $target = $this->makeUser(['protected' => true]);

    Auth::guard('web')->login($admin);

    expect($admin->impersonate($target))->toBeFalse()
        ->and(app(Impersonate::class)->isImpersonating())->toBeFalse();
});

it('does not report unrelated users as impersonated', function (): void {
    $admin = $this->makeUser(['may_impersonate' => true]);
    $target = $this->makeUser();
    $bystander = $this->makeUser();

    Auth::guard('web')->login($admin);
    $admin->impersonate($target);

    expect($bystander->isImpersonated())->toBeFalse()
        ->and($target->isImpersonated())->toBeTrue();
});

it('reports the target as impersonated when their id collides with the impersonator across classes', function (): void {
    $admin = $this->makeAdmin();
    $target = $this->makeUser();

    expect($admin->id)->toBe($target->id);

    Auth::guard('staff')->login($admin);

    expect($admin->impersonate($target, 'web'))->toBeTrue()
        ->and($target->isImpersonated())->toBeTrue();
});

it('reports isImpersonated false when no impersonation is active', function (): void {
    $user = $this->makeUser();

    Auth::guard('web')->login($user);

    expect($user->isImpersonated())->toBeFalse();
});

it('defaults canImpersonate and canBeImpersonated to true', function (): void {
    // The Admin fixture does not override the hooks, so this exercises the
    // trait's own defaults (the User fixture overrides both).
    $admin = $this->makeAdmin();

    expect($admin->canImpersonate())->toBeTrue()
        ->and($admin->canBeImpersonated())->toBeTrue();
});
