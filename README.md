# Laravel Impersonate

Modern user impersonation for Laravel. Let admins and support staff securely "log in as" another user, then return to their own session — guard-aware, event-driven, and safe with `remember me` tokens.

- Guard-aware `take` / `leave` that restores the original user in their original guard
- Nested and self impersonation are blocked
- Never mutates the target's or impersonator's `remember_token`
- Events on take/leave, a route middleware to protect sensitive actions, and Blade directives
- Zero runtime dependencies beyond `illuminate/*`

## Requirements

- PHP 8.4+
- Laravel 12 or 13

## Installation

```bash
composer require thecyrilcril/laravel-impersonate
```

The service provider is auto-discovered. Publish the config if you want to change defaults:

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
    // Zero (or a non-numeric value) disables expiry.
    'ttl' => (int) env('IMPERSONATION_TTL_MINUTES', 30),
];
```

> **Session guards only.** This is a session-driven mechanism: both the
> impersonator's guard and the target guard must be session-based. `take()`
> returns `false` (a no-op) for token/request guards such as Sanctum's `api`
> guard rather than silently pretending to succeed.

## User model

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

| Method | Description |
| --- | --- |
| `impersonate(Authenticatable $target, ?string $guard = null): bool` | Begin impersonating `$target`. Returns `false` if disallowed, or if nested/self impersonation. |
| `leaveImpersonation(): bool` | Stop impersonating and restore the original session. |
| `isImpersonated(): bool` | Whether the current session is impersonating this user. |
| `canImpersonate(): bool` | Whether this user may impersonate others. Defaults to `true` — override it. |
| `canBeImpersonated(): bool` | Whether this user may be impersonated. Defaults to `true` — override it. |

Override the two policy hooks to express your own authorization:

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

> The `Impersonate` manager itself performs **no** authorization. The trait's
> `impersonate()` enforces `canImpersonate()` / `canBeImpersonated()` before
> delegating. If you call the manager directly, gate the call yourself
> (policy, gate, or the trait hooks).

## Routes and controllers

This package intentionally ships **no** routes — you wire them to fit your app:

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

You can also resolve the manager directly:

```php
use Thecyrilcril\Impersonate\Impersonate;

$manager = app(Impersonate::class);

$manager->take($admin, $target);            // uses the default guard
$manager->take($admin, $target, 'web');     // impersonate into a specific guard
$manager->isImpersonating();                // bool
$manager->getImpersonatorId();              // int|string|null
$manager->getImpersonator();                // ?Authenticatable
$manager->leave();
```

## Protecting sensitive routes

Apply the `impersonate.protect` middleware to any route an impersonator must not
reach — password changes, two-factor management, account deletion. It returns a
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
    <a href="{{ route('impersonate.leave') }}">Leave impersonation</a>
@endImpersonating

@impersonating('web')
    Impersonating on the web guard.
@endImpersonating

@canImpersonate
    <button>Impersonate</button>
@endCanImpersonate

@canBeImpersonated($user)
    <a href="{{ route('impersonate.take', $user) }}">Log in as {{ $user->name }}</a>
@endCanBeImpersonated
```

## Events

Three events are dispatched. Every event carries an `occurredAt`
(`DateTimeInterface`) stamped when the action happened — pass it to your audit
log so a queued listener records the true time, not the job-processing time.

- `TakenImpersonation` — `impersonator`, `target`, `occurredAt`.
- `LeftImpersonation` — `impersonator`, `target`, `occurredAt`.
- `OrphanedImpersonationLeft` — dispatched instead of `LeftImpersonation` when
  the impersonator no longer exists (deleted mid-session), so the leave stays
  auditable. Carries `impersonatorId` (int|string), a nullable `target`, and
  `occurredAt` — there is no impersonator model to hand you.

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

## How guard switching works

`take()` records the impersonator's id and their original guard, logs out of
that guard **without cycling the remember token**, and logs the target into the
requested guard (defaulting to your app's default guard). `leave()` reverses it:
it logs out of the impersonation guard and logs the original impersonator back
into their original guard — again leaving remember tokens untouched.

## Testing

```bash
composer test      # Pest
composer lint      # Pint
composer analyse   # PHPStan (larastan) level 7
```

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
