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

it('defaults canImpersonate and canBeImpersonated to true', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();

    expect($admin->canImpersonate())->toBeTrue()
        ->and($target->canBeImpersonated())->toBeTrue();
});
