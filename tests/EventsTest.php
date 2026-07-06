<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Thecyrilcril\Impersonate\Events\LeftImpersonation;
use Thecyrilcril\Impersonate\Events\TakenImpersonation;
use Thecyrilcril\Impersonate\Impersonate;

it('dispatches TakenImpersonation with the correct payload', function (): void {
    Event::fake([TakenImpersonation::class, LeftImpersonation::class]);

    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    app(Impersonate::class)->take($admin, $target);

    Event::assertDispatched(TakenImpersonation::class, function (TakenImpersonation $event) use ($admin, $target): bool {
        return $event->impersonator->getAuthIdentifier() === $admin->id
            && $event->target->getAuthIdentifier() === $target->id;
    });
    Event::assertNotDispatched(LeftImpersonation::class);
});

it('dispatches LeftImpersonation with the correct payload', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    $manager = app(Impersonate::class);
    $manager->take($admin, $target);

    Event::fake([LeftImpersonation::class]);
    $manager->leave();

    Event::assertDispatched(LeftImpersonation::class, function (LeftImpersonation $event) use ($admin, $target): bool {
        return $event->impersonator->getAuthIdentifier() === $admin->id
            && $event->target->getAuthIdentifier() === $target->id;
    });
});

it('does not dispatch events on rejected attempts', function (): void {
    Event::fake([TakenImpersonation::class]);

    $admin = $this->makeUser();
    Auth::guard('web')->login($admin);

    app(Impersonate::class)->take($admin, $admin);

    Event::assertNotDispatched(TakenImpersonation::class);
});
