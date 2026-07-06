<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Session\Session;
use Thecyrilcril\Impersonate\Events\LeftImpersonation;
use Thecyrilcril\Impersonate\Events\OrphanedImpersonationLeft;
use Thecyrilcril\Impersonate\Events\TakenImpersonation;

final class Impersonate
{
    public function __construct(
        private readonly AuthFactory $auth,
        private readonly Config $config,
        private readonly Container $container,
    ) {}

    /**
     * Begin impersonating the target user.
     *
     * Returns false when already impersonating (nested impersonation is not
     * allowed) or when the impersonator would be impersonating themselves —
     * including the same user resolved through a different guard.
     *
     * The swap is quiet: no Login/Logout events fire (so the target's login
     * history and login notifications stay clean), remember tokens are never
     * touched, and the session ID is regenerated against fixation.
     */
    public function take(Authenticatable $impersonator, Authenticatable $target, ?string $guard = null): bool
    {
        if ($this->isImpersonating()) {
            return false;
        }

        $guard ??= $this->defaultGuard();

        if ($this->isSameUser($impersonator, $target)) {
            return false;
        }

        // Fail closed: refuse the swap unless we can positively identify the
        // guard the impersonator is authenticated on (never guess a default —
        // guessing can restore the wrong provider's user on leave).
        $originalGuard = $this->currentGuard($impersonator);

        if ($originalGuard === null) {
            return false;
        }

        // Both guards must be session-based; the swap is session state, so a
        // token/request guard would silently no-op and strand the session.
        if (! $this->isSessionGuard($originalGuard) || ! $this->isSessionGuard($guard)) {
            return false;
        }

        $this->session()->put($this->key('impersonator_id'), $impersonator->getAuthIdentifier());
        $this->session()->put($this->key('impersonator_type'), $impersonator::class);
        $this->session()->put($this->key('impersonator_guard'), $originalGuard);
        $this->session()->put($this->key('guard'), $guard);
        $this->session()->put($this->key('started_at'), time());

        $this->quietLogout($originalGuard);
        $this->quietLogin($guard, $target);

        $this->events()->dispatch(new TakenImpersonation($impersonator, $target));

        return true;
    }

    /**
     * Stop impersonating and restore the original impersonator in their guard.
     *
     * Returns false when no impersonation session is active. When the
     * impersonator no longer exists, the session is cleaned up and an
     * OrphanedImpersonationLeft event is dispatched so the leave remains
     * auditable.
     */
    public function leave(): bool
    {
        if (! $this->isImpersonating()) {
            return false;
        }

        $impersonatorGuard = $this->impersonatorGuard();
        $impersonateGuard = $this->impersonateGuard();
        $impersonatorId = $this->getImpersonatorId();

        $target = $this->auth->guard($impersonateGuard)->user();
        $impersonator = $this->getImpersonator();

        $this->quietLogout($impersonateGuard);

        if ($impersonator !== null) {
            $this->quietLogin($impersonatorGuard, $impersonator);
        } else {
            $this->session()->migrate(true);
        }

        $this->clear();

        if ($impersonator !== null && $target !== null) {
            $this->events()->dispatch(new LeftImpersonation($impersonator, $target));
        } elseif ($impersonatorId !== null) {
            $this->events()->dispatch(new OrphanedImpersonationLeft($impersonatorId, $target));
        }

        return true;
    }

    public function isImpersonating(): bool
    {
        return $this->session()->has($this->key('impersonator_id'));
    }

    /**
     * The impersonated user resolved on the impersonation guard, or null when
     * not impersonating or the target no longer resolves. Resolves against the
     * stored impersonation guard — never the request's default guard.
     */
    public function impersonatedUser(): ?Authenticatable
    {
        if (! $this->isImpersonating()) {
            return null;
        }

        return $this->auth->guard($this->impersonateGuard())->user();
    }

    public function getImpersonatorId(): int|string|null
    {
        /** @var int|string|null $id */
        $id = $this->session()->get($this->key('impersonator_id'));

        return $id;
    }

    public function getImpersonator(): ?Authenticatable
    {
        $id = $this->getImpersonatorId();

        if ($id === null) {
            return null;
        }

        $provider = $this->auth->guard($this->impersonatorGuard())->getProvider();
        $impersonator = $provider->retrieveById($id);

        if ($impersonator === null) {
            return null;
        }

        // Guard against a recycled id resolving to a different account: the
        // restored model must match the class captured at take-time.
        /** @var string|null $type */
        $type = $this->session()->get($this->key('impersonator_type'));

        if ($type !== null && $impersonator::class !== $type) {
            return null;
        }

        return $impersonator;
    }

    /**
     * The guard the impersonated user is authenticated on, or null when the
     * session is not impersonating.
     */
    public function impersonatingOnGuard(): ?string
    {
        return $this->isImpersonating() ? $this->impersonateGuard() : null;
    }

    /**
     * Unix timestamp of when the impersonation started, or null when the
     * session is not impersonating (or predates TTL support).
     */
    public function startedAt(): ?int
    {
        /** @var int|null $startedAt */
        $startedAt = $this->session()->get($this->key('started_at'));

        return $startedAt;
    }

    /**
     * Whether the active impersonation has outlived the configured TTL.
     * Sessions without a started_at stamp never expire (backward compat),
     * and a TTL of zero/null disables expiry entirely.
     */
    public function hasExpired(): bool
    {
        if (! $this->isImpersonating()) {
            return false;
        }

        $ttlMinutes = (int) $this->config->get('impersonate.ttl', 0);
        $startedAt = $this->startedAt();

        if ($ttlMinutes <= 0 || $startedAt === null) {
            return false;
        }

        return (time() - $startedAt) >= ($ttlMinutes * 60);
    }

    /**
     * Whole minutes until the active impersonation expires; null when no
     * impersonation is active or expiry is disabled.
     */
    public function minutesRemaining(): ?int
    {
        $ttlMinutes = (int) $this->config->get('impersonate.ttl', 0);
        $startedAt = $this->startedAt();

        if (! $this->isImpersonating() || $ttlMinutes <= 0 || $startedAt === null) {
            return null;
        }

        $remaining = ($startedAt + $ttlMinutes * 60) - time();

        return max(0, (int) ceil($remaining / 60));
    }

    /**
     * Log the user into the guard without firing Login events, touching the
     * remember token, or leaving the session ID intact (fixation defense).
     */
    private function quietLogin(string $guard, Authenticatable $user): void
    {
        $driver = $this->auth->guard($guard);

        if (method_exists($driver, 'getName')) {
            $driver->setUser($user);
            $this->session()->put($driver->getName(), $user->getAuthIdentifier());
            $this->session()->migrate(true);

            return;
        }

        // Non-session guards fall back to a plain login without remember-me.
        if (method_exists($driver, 'login')) {
            $driver->login($user, false);
        }
    }

    /**
     * Log out of the guard without firing Logout events or cycling the
     * user's remember token.
     */
    private function quietLogout(string $guard): void
    {
        $driver = $this->auth->guard($guard);

        if (method_exists($driver, 'getName')) {
            $this->session()->forget($driver->getName());

            if (method_exists($driver, 'forgetUser')) {
                $driver->forgetUser();
            }

            return;
        }

        if (method_exists($driver, 'logoutCurrentDevice')) {
            $driver->logoutCurrentDevice();

            return;
        }

        if (method_exists($driver, 'logout')) {
            $driver->logout();
        }
    }

    private function session(): Session
    {
        /** @var Session $session */
        $session = $this->container->make('session.store');

        return $session;
    }

    private function events(): Dispatcher
    {
        /** @var Dispatcher $events */
        $events = $this->container->make(Dispatcher::class);

        return $events;
    }

    private function clear(): void
    {
        $this->session()->forget($this->key('impersonator_id'));
        $this->session()->forget($this->key('impersonator_type'));
        $this->session()->forget($this->key('impersonator_guard'));
        $this->session()->forget($this->key('guard'));
        $this->session()->forget($this->key('started_at'));
    }

    /**
     * Same human: identical identifier on the same Authenticatable class is
     * self-impersonation regardless of which guard resolves them.
     */
    private function isSameUser(Authenticatable $impersonator, Authenticatable $target): bool
    {
        return $impersonator::class === $target::class
            && $impersonator->getAuthIdentifier() === $target->getAuthIdentifier();
    }

    /**
     * Whether the named guard is session-based (the only kind this
     * session-driven mechanism can drive coherently).
     */
    private function isSessionGuard(string $guard): bool
    {
        // getName() is the session-store key accessor, present only on
        // SessionGuard — token/request guards lack it.
        return method_exists($this->auth->guard($guard), 'getName');
    }

    private function impersonatorGuard(): string
    {
        /** @var string|null $guard */
        $guard = $this->session()->get($this->key('impersonator_guard'));

        return $guard ?? $this->defaultGuard();
    }

    private function impersonateGuard(): string
    {
        /** @var string|null $guard */
        $guard = $this->session()->get($this->key('guard'));

        return $guard ?? $this->defaultGuard();
    }

    /**
     * The guard the impersonator is already authenticated on, or null when it
     * cannot be positively identified (caller must fail closed).
     *
     * Only inspects guards that ALREADY hold a resolved user in memory
     * (hasUser()) — it never calls user()/check(), which would resolve
     * remember-me recaller cookies and, as a side effect, log a user in and
     * fire a Login event (defeating the quiet-swap guarantee).
     */
    private function currentGuard(Authenticatable $impersonator): ?string
    {
        foreach (array_keys((array) $this->config->get('auth.guards', [])) as $name) {
            $guard = $this->auth->guard($name);

            if (! $guard instanceof StatefulGuard || ! $guard->hasUser()) {
                continue;
            }

            $user = $guard->user();

            if ($user !== null
                && $user::class === $impersonator::class
                && $user->getAuthIdentifier() === $impersonator->getAuthIdentifier()
            ) {
                return (string) $name;
            }
        }

        return null;
    }

    private function defaultGuard(): string
    {
        /** @var string|null $guard */
        $guard = $this->config->get('impersonate.default_impersonator_guard')
            ?? $this->config->get('auth.defaults.guard');

        return $guard ?? 'web';
    }

    private function key(string $suffix): string
    {
        /** @var string $prefix */
        $prefix = $this->config->get('impersonate.session_key', 'impersonate');

        return "{$prefix}.{$suffix}";
    }
}
