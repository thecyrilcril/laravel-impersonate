<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Thecyrilcril\Impersonate\Impersonate;

/**
 * Blocks a request while the session is actively impersonating another user.
 *
 * Apply to sensitive routes (password change, two-factor management, account
 * deletion) so an impersonator cannot perform them on the target's behalf.
 *
 * Keys on isActive(), not isImpersonating(): an expired-but-not-yet-torn-down
 * session must not keep blocking the operator's own sensitive routes. Expiry
 * teardown itself is owned by HandleImpersonationSession; this middleware only
 * decides whether an *active* impersonation should block the route.
 */
final class ProtectFromImpersonation
{
    public function __construct(private readonly Impersonate $impersonate) {}

    public function handle(Request $request, Closure $next): Response
    {
        if ($this->impersonate->isActive()) {
            abort(403, 'This action is not available while impersonating a user.');
        }

        return $next($request);
    }
}
