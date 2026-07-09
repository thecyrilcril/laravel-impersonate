<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Session Key Prefix
    |--------------------------------------------------------------------------
    |
    | The package's INTERNAL impersonation state is stored under keys namespaced
    | with this prefix (e.g. "impersonate.impersonator_id"). Change it only if
    | it collides with existing session keys in your application.
    |
    | Note: the "impersonate.status" flash key written on auto-teardown (see
    | HandleImpersonationSession) is a FIXED public contract and is NOT scoped
    | by this prefix — your status listener reads "impersonate.status" verbatim.
    | Do not store your own unrelated session data under this prefix's root; a
    | future suffix collision (or a prefix change) would entangle it with the
    | package's own keys.
    |
    */

    'session_key' => 'impersonate',

    /*
    |--------------------------------------------------------------------------
    | Default Impersonator Guard
    |--------------------------------------------------------------------------
    |
    | The guard used to resolve the impersonator and the target when no guard
    | is passed explicitly to take()/leave(). Defaults to your application's
    | default auth guard.
    |
    */

    'default_impersonator_guard' => config('auth.defaults.guard'),

    /*
    |--------------------------------------------------------------------------
    | Leave Redirect Target
    |--------------------------------------------------------------------------
    |
    | Where your application should redirect after leaving impersonation. This
    | package does not register routes; use this value in your own controller
    | when wiring the "leave impersonation" endpoint.
    |
    */

    'leave_redirect_to' => '/',

    /*
    |--------------------------------------------------------------------------
    | Impersonation TTL (minutes)
    |--------------------------------------------------------------------------
    |
    | How long an impersonation session may live before the
    | HandleImpersonationSession middleware ends it automatically. Zero (or
    | null) disables expiry. Sessions started before TTL support never expire.
    |
    */

    'ttl' => (int) env('IMPERSONATION_TTL_MINUTES', 30),

];
