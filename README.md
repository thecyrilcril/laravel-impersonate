# Laravel Impersonate

User impersonation for Laravel. It lets an admin or support person "log in as" another user, fix a problem, and then switch back to their own account.

- Guard-aware: `take()` and `leave()` put the admin back on the guard they came from
- Blocks impersonating yourself, and blocks starting an impersonation inside another one
- Never changes anyone's `remember_token`, so nobody gets logged out of their other devices
- Fires events on take and leave, so you can build an audit trail
- Ships a middleware that keeps impersonators out of sensitive pages, and one that auto-ends stale impersonations
- Adds Blade directives for your views
- Needs nothing outside Laravel's own `illuminate/*` packages

## Requirements

- PHP 8.4 or newer
- Laravel 12 or 13

## Installation

```bash
composer require thecyrilcril/laravel-impersonate
```

The service provider is found automatically. Publish the config if you want to change the defaults:

```bash
php artisan vendor:publish --tag=impersonate-config
```

This writes `config/impersonate.php`:

```php
return [
    'session_key' => 'impersonate',
    'default_impersonator_guard' => config('auth.defaults.guard'),
    'leave_redirect_to' => '/',

    // Minutes before HandleImpersonationSession auto-ends an impersonation.
    // Zero (or a non-numeric value) turns expiry off.
    'ttl' => (int) env('IMPERSONATION_TTL_MINUTES', 30),
];
```

> **Session guards only.** Impersonation lives in the session. Both guards — the
> admin's and the target's — must be session guards. On a token or request
> guard (like Sanctum's `api` guard), `take()` does nothing and returns
> `false`. It never pretends to succeed.

## Set up your User model

Add the `ImpersonatesUsers` trait to your authenticatable model:

```php
use Illuminate\Foundation\Auth\User as Authenticatable;
use Thecyrilcril\Impersonate\Concerns\ImpersonatesUsers;

final class User extends Authenticatable
{
    use ImpersonatesUsers;
}
```

The trait adds:

| Method | What it does |
| --- | --- |
| `impersonate(Authenticatable $target, ?string $guard = null): bool` | Start impersonating `$target`. Returns `false` when not allowed, already impersonating, or the target is you. |
| `leaveImpersonation(): bool` | Stop impersonating and return to your own session. |
| `isImpersonated(): bool` | True while the signed-in user is being impersonated. Call it on the current user. |
| `canImpersonate(): bool` | May this user impersonate others? Defaults to `true` — override it. |
| `canBeImpersonated(): bool` | May others impersonate this user? Defaults to `true` — override it. |

Override the two hooks to set your own rules:

```php
public function canImpersonate(): bool
{
    return $this->hasRole('admin');
}

public function canBeImpersonated(): bool
{
    return ! $this->hasRole('super-admin');
}
```

> The `Impersonate` manager does **no** permission checks on its own. The
> trait's `impersonate()` checks `canImpersonate()` and `canBeImpersonated()`
> first, then hands off to the manager. If you call the manager directly, add
> your own checks (a policy, a gate, or the trait hooks).

## Add your routes

The package ships **no** routes on purpose — you wire them the way your app
needs. Use POST (or DELETE) so the actions are CSRF-protected; never GET:

```php
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

Route::post('/impersonate/{user}', function (User $user) {
    Auth::user()->impersonate($user);

    return redirect('/');
})->middleware('auth')->name('impersonate.take');

Route::post('/impersonate/leave', function () {
    Auth::user()->leaveImpersonation();

    return redirect(config('impersonate.leave_redirect_to'));
})->middleware('auth')->name('impersonate.leave');
```

## The manager — full API

You can also use the manager directly:

```php
use Thecyrilcril\Impersonate\Impersonate;

$manager = app(Impersonate::class);

// Start and stop
$manager->take($admin, $target);            // uses the default guard
$manager->take($admin, $target, 'web');     // logs the target into a chosen guard
$manager->leave();                          // restores the admin

// State
$manager->isImpersonating();                // bool — impersonation keys exist in the session
$manager->isActive();                       // bool — impersonating AND not expired
$manager->getImpersonatorId();              // int|string|null — the admin's id
$manager->getImpersonator();                // ?Authenticatable — the admin, or null if deleted
$manager->impersonatedUser();               // ?Authenticatable — the user being impersonated
$manager->impersonatingOnGuard();           // ?string — the guard the target is logged into
$manager->restoreGuard();                   // ?string — the guard the admin returns to on leave()

// Expiry (TTL)
$manager->startedAt();                      // ?int — unix time the impersonation began
$manager->hasExpired();                     // bool — true when it outlived the TTL
$manager->minutesRemaining();               // ?int — whole minutes left; null when expiry is off
```

Two things to know:

- `isImpersonating()` only says the session keys exist. An expired
  impersonation still reads as `true` until the session middleware cleans it
  up on the next request. **For any security decision, use `isActive()`.**
- `take()` returns `false` instead of throwing. That happens when the session
  is already impersonating (no nesting), the target is the same user, the
  admin's current guard cannot be safely identified, or either guard is not a
  session guard.

Multi-guard apps: after `leave()`, redirect the admin to a page protected by
the guard `restoreGuard()` reports. A redirect to a page on a different guard
bounces the just-restored admin to the login screen. Single-guard apps can
ignore this.

## Auto-ending stale impersonations (TTL)

The `ttl` config sets how many minutes an impersonation may live. **It only
works when the `HandleImpersonationSession` middleware runs.** The package
registers the alias `impersonate.session` but does not add the middleware to
any group — do that yourself in `bootstrap/app.php`:

```php
use Thecyrilcril\Impersonate\Http\Middleware\HandleImpersonationSession;

->withMiddleware(function (Middleware $middleware): void {
    $middleware->web(append: [
        HandleImpersonationSession::class,
    ]);
})
```

On every request, the middleware:

- ends the impersonation when it is older than the TTL,
- ends the impersonation when the impersonated user no longer exists.

Both cases redirect to `leave_redirect_to` and flash a reason into the session
under the fixed key `impersonate.status`:

| Status | Meaning |
| --- | --- |
| `expired` | The impersonation outlived the TTL. |
| `target-missing` | The impersonated user was deleted. |

Read that key in your layout to show a toast or banner. Set `ttl` to `0` to
turn expiry off. Without the middleware, `ttl` has no effect and nothing
expires.

## Protecting sensitive routes

Add the `impersonate.protect` middleware to any route an impersonator must not
reach — password changes, two-factor settings, account deletion. It returns
`403` while impersonating:

```php
Route::middleware(['auth', 'impersonate.protect'])->group(function () {
    Route::put('/settings/password', PasswordController::class);
    Route::post('/settings/two-factor', TwoFactorController::class);
});
```

## Blade directives

```blade
@impersonating
    <form method="POST" action="{{ route('impersonate.leave') }}">
        @csrf
        <button type="submit">Leave impersonation</button>
    </form>
@endImpersonating

@impersonating('web')
    Impersonating on the web guard.
@endImpersonating

@canImpersonate
    <button>Impersonate</button>
@endCanImpersonate

@canImpersonate('admin')
    {{-- checks the user signed into the "admin" guard --}}
@endCanImpersonate

@canBeImpersonated($user)
    <a href="{{ route('impersonate.take', $user) }}">Log in as {{ $user->name }}</a>
@endCanBeImpersonated
```

`@impersonating` and `@canImpersonate` take an optional guard name.
`@canImpersonate` checks the signed-in user's `canImpersonate()` hook;
`@canBeImpersonated($user)` checks the given user's `canBeImpersonated()` hook.

## Events

Three events are fired. Every event carries an `occurredAt`
(`DateTimeInterface`) stamped when the action happened — pass it to your audit
log so a queued listener records the true time, not the time the job ran. All
three use `SerializesModels`, so queued listeners are safe.

- `TakenImpersonation` — `impersonator`, `target`, `occurredAt`.
- `LeftImpersonation` — `impersonator`, `target`, `occurredAt`.
- `OrphanedImpersonationLeft` — fired instead of `LeftImpersonation` when the
  impersonator no longer exists (deleted mid-session), so the leave still
  reaches your audit log. Carries `impersonatorId` (int|string), a nullable
  `target`, and `occurredAt` — there is no impersonator model left to give you.

```php
use Thecyrilcril\Impersonate\Events\OrphanedImpersonationLeft;
use Thecyrilcril\Impersonate\Events\TakenImpersonation;

Event::listen(TakenImpersonation::class, function (TakenImpersonation $event) {
    logger()->info('Impersonation started', [
        'impersonator' => $event->impersonator->getAuthIdentifier(),
        'target' => $event->target->getAuthIdentifier(),
        'at' => $event->occurredAt,
    ]);
});

Event::listen(OrphanedImpersonationLeft::class, function (OrphanedImpersonationLeft $event) {
    logger()->warning('Impersonation left; impersonator was deleted', [
        'impersonator_id' => $event->impersonatorId,
    ]);
});
```

## Guarding against reused ids (fingerprints)

Databases can hand an auto-increment id to a new row after the old one is
deleted. If the admin's account is deleted mid-impersonation and a **new**
user gets their old id, `leave()` could restore the wrong person. To close
that door, give your model a stable fingerprint — a value that never moves to
another human, like a UUID:

```php
public function getImpersonationFingerprint(): string
{
    return $this->uuid;
}
```

The package captures the fingerprint at `take()` and checks it at `leave()`.
A mismatch means a different human: the session is cleaned up instead of
restored, and `OrphanedImpersonationLeft` is fired. This is opt-in — without
the method, the package still requires the restored user's id **and** class to
match what was captured.

## How guard switching works

`take()` remembers the admin's id and guard, then swaps users quietly:

- No `Login`/`Logout` events fire, so the target's login history and
  "new device" emails stay clean.
- Remember tokens are never touched, so nobody is logged out of their other
  devices.
- The session id is regenerated, which blocks session fixation.

`leave()` reverses the swap: it logs out of the impersonation guard and logs
the admin back into their original guard — again without touching remember
tokens. Two overlapping take/leave calls on the same session (say, two browser
tabs) are run one at a time when your cache store supports atomic locks.

## Testing

```bash
composer test      # Pest
composer lint      # Pint
composer analyse   # PHPStan (larastan) level 7
```

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
