<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Thecyrilcril\Impersonate\Impersonate;

/**
 * Blocks a request while the session is impersonating another user.
 *
 * Apply to sensitive routes (password change, two-factor management, account
 * deletion) so an impersonator cannot perform them on the target's behalf.
 */
final class ProtectFromImpersonation
{
    public function __construct(private readonly Impersonate $impersonate) {}

    public function handle(Request $request, Closure $next): Response
    {
        if ($this->impersonate->isImpersonating()) {
            abort(403, 'This action is not available while impersonating a user.');
        }

        return $next($request);
    }
}
