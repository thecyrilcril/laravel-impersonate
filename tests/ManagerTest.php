<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Thecyrilcril\Impersonate\Impersonate;

it('takes and leaves impersonation, restoring the impersonator', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();

    Auth::guard('web')->login($admin);

    $manager = app(Impersonate::class);

    expect($manager->take($admin, $target))->toBeTrue()
        ->and($manager->isImpersonating())->toBeTrue()
        ->and(Auth::guard('web')->id())->toBe($target->id)
        ->and($manager->getImpersonatorId())->toBe($admin->id)
        ->and($manager->getImpersonator()?->id)->toBe($admin->id);

    expect($manager->leave())->toBeTrue()
        ->and($manager->isImpersonating())->toBeFalse()
        ->and(Auth::guard('web')->id())->toBe($admin->id);
});

it('blocks nested impersonation', function (): void {
    $admin = $this->makeUser();
    $first = $this->makeUser();
    $second = $this->makeUser();

    Auth::guard('web')->login($admin);
    $manager = app(Impersonate::class);

    expect($manager->take($admin, $first))->toBeTrue()
        ->and($manager->take($admin, $second))->toBeFalse()
        ->and(Auth::guard('web')->id())->toBe($first->id);
});

it('blocks self impersonation in the same guard', function (): void {
    $admin = $this->makeUser();
    Auth::guard('web')->login($admin);

    $manager = app(Impersonate::class);

    expect($manager->take($admin, $admin))->toBeFalse()
        ->and($manager->isImpersonating())->toBeFalse();
});

it('switches guards when taking and restores the original guard on leave', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();

    Auth::guard('admin')->login($admin);

    $manager = app(Impersonate::class);

    expect($manager->take($admin, $target, 'web'))->toBeTrue()
        ->and(Auth::guard('web')->id())->toBe($target->id)
        ->and(Auth::guard('admin')->check())->toBeFalse();

    expect($manager->leave())->toBeTrue()
        ->and(Auth::guard('admin')->id())->toBe($admin->id)
        ->and(Auth::guard('web')->check())->toBeFalse();
});

it('refuses to impersonate the same user even across different guards', function (): void {
    $admin = $this->makeUser();

    Auth::guard('admin')->login($admin);
    $manager = app(Impersonate::class);

    // Same model class + identifier is the same human — self-impersonation
    // regardless of which guard resolves them.
    expect($manager->take($admin, $admin, 'web'))->toBeFalse()
        ->and($manager->isImpersonating())->toBeFalse();
});

it('returns false when leaving without an active impersonation', function (): void {
    expect(app(Impersonate::class)->leave())->toBeFalse();
});

it('reports no impersonator id when not impersonating', function (): void {
    $manager = app(Impersonate::class);

    expect($manager->getImpersonatorId())->toBeNull()
        ->and($manager->getImpersonator())->toBeNull();
});

it('exposes the impersonator class through getImpersonatorType', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();

    Auth::guard('web')->login($admin);
    $manager = app(Impersonate::class);

    expect($manager->getImpersonatorType())->toBeNull();

    $manager->take($admin, $target);

    expect($manager->getImpersonatorType())->toBe($admin::class);

    $manager->leave();

    expect($manager->getImpersonatorType())->toBeNull();
});

it('clears all session keys after leaving', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();

    Auth::guard('web')->login($admin);
    $manager = app(Impersonate::class);
    $manager->take($admin, $target);
    $manager->leave();

    expect(session()->has('impersonate.impersonator_id'))->toBeFalse()
        ->and(session()->has('impersonate.impersonator_guard'))->toBeFalse()
        ->and(session()->has('impersonate.guard'))->toBeFalse();
});

it('never mutates the remember token across take and leave', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();

    Auth::guard('web')->login($admin);
    $manager = app(Impersonate::class);

    $manager->take($admin, $target);
    $manager->leave();

    expect($admin->fresh()->remember_token)->toBe('original-token')
        ->and($target->fresh()->remember_token)->toBe('original-token');
});
