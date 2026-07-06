<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Thecyrilcril\Impersonate\Events\OrphanedImpersonationLeft;
use Thecyrilcril\Impersonate\Http\Middleware\HandleImpersonationSession;
use Thecyrilcril\Impersonate\Impersonate;
use Thecyrilcril\Impersonate\ImpersonateServiceProvider;

it('regenerates the session id on take and on leave', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    $manager = app(Impersonate::class);

    $idBeforeTake = session()->getId();
    $manager->take($admin, $target);
    $idAfterTake = session()->getId();

    expect($idAfterTake)->not->toBe($idBeforeTake);

    $manager->leave();

    expect(session()->getId())->not->toBe($idAfterTake);
});

it('fires no Login or Logout events during take and leave', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    Event::fake([Login::class, Logout::class]);

    $manager = app(Impersonate::class);
    $manager->take($admin, $target);
    $manager->leave();

    Event::assertNotDispatched(Login::class);
    Event::assertNotDispatched(Logout::class);
});

it('leaves the remember token untouched across take and leave', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();
    $target->setRememberToken('target-token');
    $adminToken = $admin->getRememberToken();

    Auth::guard('web')->login($admin);

    $manager = app(Impersonate::class);
    $manager->take($admin, $target);
    $manager->leave();

    expect($target->getRememberToken())->toBe('target-token')
        ->and($admin->getRememberToken())->toBe($adminToken);
});

it('honors a custom session key prefix in guard-scoped directive checks', function (): void {
    config()->set('impersonate.session_key', 'custom-prefix');

    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    app(Impersonate::class)->take($admin, $target, 'web');

    expect(ImpersonateServiceProvider::isImpersonating('web'))->toBeTrue()
        ->and(ImpersonateServiceProvider::isImpersonating('admin'))->toBeFalse()
        ->and(session()->has('custom-prefix.impersonator_id'))->toBeTrue();
});

it('dispatches OrphanedImpersonationLeft when the impersonator was deleted', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    $manager = app(Impersonate::class);
    $manager->take($admin, $target);

    $adminId = $admin->id;
    $admin->delete();

    Event::fake([OrphanedImpersonationLeft::class]);

    expect($manager->leave())->toBeTrue()
        ->and($manager->isImpersonating())->toBeFalse();

    Event::assertDispatched(
        OrphanedImpersonationLeft::class,
        fn (OrphanedImpersonationLeft $event): bool => $event->impersonatorId === $adminId,
    );
});

it('expires an impersonation past the configured ttl', function (): void {
    config()->set('impersonate.ttl', 30);

    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    $manager = app(Impersonate::class);
    $manager->take($admin, $target);

    expect($manager->hasExpired())->toBeFalse()
        ->and($manager->minutesRemaining())->toBeGreaterThan(0);

    session()->put('impersonate.started_at', time() - 31 * 60);

    expect($manager->hasExpired())->toBeTrue()
        ->and($manager->minutesRemaining())->toBe(0);
});

it('never expires with a zero ttl or a legacy session without started_at', function (): void {
    config()->set('impersonate.ttl', 0);

    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    $manager = app(Impersonate::class);
    $manager->take($admin, $target);

    expect($manager->hasExpired())->toBeFalse()
        ->and($manager->minutesRemaining())->toBeNull();

    config()->set('impersonate.ttl', 30);
    session()->forget('impersonate.started_at');

    expect($manager->hasExpired())->toBeFalse();
});

it('auto-ends an expired impersonation via the session middleware', function (): void {
    config()->set('impersonate.ttl', 30);
    config()->set('impersonate.leave_redirect_to', '/came-back');

    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    $manager = app(Impersonate::class);
    $manager->take($admin, $target);
    session()->put('impersonate.started_at', time() - 31 * 60);

    $middleware = app(HandleImpersonationSession::class);
    $response = $middleware->handle(Request::create('/probe'), static fn (): Response => new Response('ok'));

    expect($response)->toBeInstanceOf(RedirectResponse::class)
        ->and($response->getTargetUrl())->toContain('/came-back')
        ->and($manager->isImpersonating())->toBeFalse();
});

it('cleans up when the impersonated user no longer exists', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    $manager = app(Impersonate::class);
    $manager->take($admin, $target);

    $target->delete();
    Auth::guard('web')->forgetUser();

    $request = Request::create('/probe');
    $request->setUserResolver(static fn (): ?Illuminate\Contracts\Auth\Authenticatable => Auth::guard('web')->user());

    $middleware = app(HandleImpersonationSession::class);
    $response = $middleware->handle($request, static fn (): Response => new Response('ok'));

    expect($response)->toBeInstanceOf(RedirectResponse::class)
        ->and($manager->isImpersonating())->toBeFalse();
});

it('passes healthy impersonation and plain requests through the session middleware', function (): void {
    $middleware = app(HandleImpersonationSession::class);

    // Not impersonating: pass-through.
    $plain = $middleware->handle(Request::create('/probe'), static fn (): Response => new Response('ok'));
    expect($plain->getContent())->toBe('ok');

    // Impersonating within TTL with a live target: pass-through.
    config()->set('impersonate.ttl', 30);
    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);
    app(Impersonate::class)->take($admin, $target);

    $request = Request::create('/probe');
    $request->setUserResolver(static fn (): ?Illuminate\Contracts\Auth\Authenticatable => Auth::guard('web')->user());

    $healthy = $middleware->handle($request, static fn (): Response => new Response('ok'));
    expect($healthy->getContent())->toBe('ok');
});

it('registers the session middleware alias', function (): void {
    expect(app('router')->getMiddleware())
        ->toHaveKey('impersonate.session', HandleImpersonationSession::class);
});

it('fails closed when the impersonator is not authenticated on any guard', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();

    // $admin is never logged in — currentGuard() can't identify an origin.
    $manager = app(Impersonate::class);

    expect($manager->take($admin, $target))->toBeFalse()
        ->and($manager->isImpersonating())->toBeFalse();
});

it('does not resolve remember-me cookies while identifying the origin guard', function (): void {
    // A guard with no in-memory user must be skipped, not resolved (which
    // would fire a Login event). Only the acting guard has a resolved user.
    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    Event::fake([Login::class]);

    expect(app(Impersonate::class)->take($admin, $target))->toBeTrue();

    Event::assertNotDispatched(Login::class);
});

it('stores the impersonator model class and rejects a recycled id on leave', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('web')->login($admin);

    $manager = app(Impersonate::class);
    $manager->take($admin, $target);

    // Simulate id recycling: the stored class no longer matches the row.
    session()->put('impersonate.impersonator_type', 'App\\SomeOtherModel');

    expect($manager->getImpersonator())->toBeNull();

    // leave() then treats it as orphaned rather than logging in the wrong user.
    Event::fake([OrphanedImpersonationLeft::class]);
    expect($manager->leave())->toBeTrue()
        ->and($manager->isImpersonating())->toBeFalse();
    Event::assertDispatched(OrphanedImpersonationLeft::class);
});

it('exposes the impersonated user via the impersonation guard, not the default', function (): void {
    $admin = $this->makeUser();
    $target = $this->makeUser();
    Auth::guard('admin')->login($admin);

    $manager = app(Impersonate::class);
    $manager->take($admin, $target, 'web');

    // Impersonation lives on web while the admin guard (where the operator
    // was) is logged out, yet impersonatedUser() still resolves the target.
    expect($manager->impersonatedUser()?->getAuthIdentifier())->toBe($target->id)
        ->and($manager->impersonatingOnGuard())->toBe('web')
        ->and($manager->startedAt())->toBeInt();
});

it('returns null accessors when not impersonating', function (): void {
    $manager = app(Impersonate::class);

    expect($manager->impersonatedUser())->toBeNull()
        ->and($manager->impersonatingOnGuard())->toBeNull()
        ->and($manager->startedAt())->toBeNull();
});
