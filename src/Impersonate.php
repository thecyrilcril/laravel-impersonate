<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Session\Session;
use Thecyrilcril\Impersonate\Events\LeftImpersonation;
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
     * allowed) or when the impersonator would be impersonating themselves.
     */
    public function take(Authenticatable $impersonator, Authenticatable $target, ?string $guard = null): bool
    {
        if ($this->isImpersonating()) {
            return false;
        }

        $guard ??= $this->defaultGuard();
        $originalGuard = $this->currentGuard($impersonator);

        if ($this->isSameUser($impersonator, $originalGuard, $target, $guard)) {
            return false;
        }

        $this->session()->put($this->key('impersonator_id'), $impersonator->getAuthIdentifier());
        $this->session()->put($this->key('impersonator_guard'), $originalGuard);
        $this->session()->put($this->key('guard'), $guard);

        $this->logoutWithoutCyclingToken($originalGuard);
        $this->auth->guard($guard)->login($target, false);

        $this->events()->dispatch(new TakenImpersonation($impersonator, $target));

        return true;
    }

    /**
     * Stop impersonating and restore the original impersonator in their guard.
     *
     * Returns false when no impersonation session is active.
     */
    public function leave(): bool
    {
        if (! $this->isImpersonating()) {
            return false;
        }

        $impersonatorGuard = $this->impersonatorGuard();
        $impersonateGuard = $this->impersonateGuard();

        $target = $this->auth->guard($impersonateGuard)->user();
        $impersonator = $this->getImpersonator();

        $this->logoutWithoutCyclingToken($impersonateGuard);

        if ($impersonator !== null) {
            $this->auth->guard($impersonatorGuard)->login($impersonator, false);
        }

        $this->clear();

        if ($impersonator !== null && $target !== null) {
            $this->events()->dispatch(new LeftImpersonation($impersonator, $target));
        }

        return true;
    }

    public function isImpersonating(): bool
    {
        return $this->session()->has($this->key('impersonator_id'));
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

        return $provider->retrieveById($id);
    }

    /**
     * Log out of the given guard without cycling the user's remember token.
     *
     * Impersonation must never mutate remember tokens, so we use
     * logoutCurrentDevice() when available (it clears the session but leaves
     * the token intact) and fall back to logout() for non-session guards.
     */
    private function logoutWithoutCyclingToken(string $guard): void
    {
        $driver = $this->auth->guard($guard);

        if (method_exists($driver, 'logoutCurrentDevice')) {
            $driver->logoutCurrentDevice();

            return;
        }

        $driver->logout();
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
        $this->session()->forget($this->key('impersonator_guard'));
        $this->session()->forget($this->key('guard'));
    }

    private function isSameUser(Authenticatable $impersonator, string $impersonatorGuard, Authenticatable $target, string $targetGuard): bool
    {
        return $impersonatorGuard === $targetGuard
            && $impersonator->getAuthIdentifier() === $target->getAuthIdentifier();
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

    private function currentGuard(Authenticatable $impersonator): string
    {
        foreach (array_keys((array) $this->config->get('auth.guards', [])) as $name) {
            $guard = $this->auth->guard($name);
            $user = $guard->user();

            if ($user !== null && $user->getAuthIdentifier() === $impersonator->getAuthIdentifier()) {
                return (string) $name;
            }
        }

        return $this->defaultGuard();
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
