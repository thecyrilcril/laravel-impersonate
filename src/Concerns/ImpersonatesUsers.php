<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Thecyrilcril\Impersonate\Impersonate;

/**
 * Adds impersonation helpers to a User model.
 *
 * The manager itself performs no authorization; these trait helpers enforce
 * the canImpersonate()/canBeImpersonated() hooks before delegating to it.
 * Override those hooks in your model to express your own policy.
 */
trait ImpersonatesUsers
{
    /**
     * Begin impersonating the target user.
     *
     * Returns false when this user may not impersonate, when the target may
     * not be impersonated, or when the manager rejects the attempt (nested or
     * self impersonation).
     */
    public function impersonate(Authenticatable $target, ?string $guard = null): bool
    {
        if (! $this->canImpersonate()) {
            return false;
        }

        if ($target instanceof self && ! $target->canBeImpersonated()) {
            return false;
        }

        return app(Impersonate::class)->take($this, $target, $guard);
    }

    /**
     * Stop impersonating and restore this user's original session.
     */
    public function leaveImpersonation(): bool
    {
        return app(Impersonate::class)->leave();
    }

    /**
     * Determine whether the current session is impersonating this user.
     *
     * True only for the user actually being impersonated — matched by class
     * AND identifier, so an id shared with a different Authenticatable class
     * neither hides the real target nor flags a bystander.
     */
    public function isImpersonated(): bool
    {
        $manager = app(Impersonate::class);

        if (! $manager->isImpersonating()) {
            return false;
        }

        $impersonated = $manager->impersonatedUser();

        return $impersonated !== null
            && $impersonated::class === $this::class
            && $impersonated->getAuthIdentifier() === $this->getAuthIdentifier();
    }

    /**
     * Whether this user is allowed to impersonate others.
     *
     * Override in your model to enforce your own authorization policy.
     */
    public function canImpersonate(): bool
    {
        return true;
    }

    /**
     * Whether this user may be impersonated by someone else.
     *
     * Override in your model to enforce your own authorization policy.
     */
    public function canBeImpersonated(): bool
    {
        return true;
    }
}
