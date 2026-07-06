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

it('stamps events with the time the impersonation occurred', function (): void {
    Event::fake([TakenImpersonation::class]);

    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    $before = new DateTimeImmutable;
    app(Impersonate::class)->take($admin, $target);
    $after = new DateTimeImmutable;

    Event::assertDispatched(TakenImpersonation::class, function (TakenImpersonation $event) use ($before, $after): bool {
        return $event->occurredAt instanceof DateTimeInterface
            && $event->occurredAt >= $before
            && $event->occurredAt <= $after;
    });
});

it('accepts an explicit occurredAt on construction', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();
    $moment = new DateTimeImmutable('2026-01-01 12:00:00');

    $event = new LeftImpersonation($admin, $target, $moment);

    expect($event->occurredAt)->toBe($moment);
});

it('does not dispatch events on rejected attempts', function (): void {
    Event::fake([TakenImpersonation::class]);

    $admin = $this->makeUser();
    Auth::guard('web')->login($admin);

    app(Impersonate::class)->take($admin, $admin);

    Event::assertNotDispatched(TakenImpersonation::class);
});
