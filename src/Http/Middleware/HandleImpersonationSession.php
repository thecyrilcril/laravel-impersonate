<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Http\Middleware;

use Closure;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Thecyrilcril\Impersonate\Impersonate;

/**
 * Keeps an active impersonation session healthy on every request.
 *
 * - Ends the impersonation when it outlives the configured TTL
 *   (config('impersonate.ttl'), minutes; zero/null disables expiry).
 * - Ends the impersonation when the impersonated user no longer exists,
 *   instead of leaving orphaned impersonation keys in a logged-out session.
 *
 * Append to the web middleware group (or alias 'impersonate.session').
 */
final class HandleImpersonationSession
{
    public function __construct(
        private readonly Impersonate $impersonate,
        private readonly Config $config,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->impersonate->isImpersonating()) {
            return $next($request);
        }

        if ($this->impersonate->hasExpired()) {
            $this->impersonate->leave();

            return $this->redirect($request, 'expired');
        }

        // Resolve the target on the impersonation guard, not the request's
        // default guard — impersonation may run on a non-default guard, and
        // $request->user() (default guard) would false-positive a teardown.
        if ($this->impersonate->impersonatedUser() === null) {
            $this->impersonate->leave();

            return $this->redirect($request, 'target-missing');
        }

        return $next($request);
    }

    private function redirect(Request $request, string $status): RedirectResponse
    {
        if ($request->hasSession()) {
            $request->session()->flash('impersonate.status', $status);
        }

        /** @var string $to */
        $to = $this->config->get('impersonate.leave_redirect_to', '/');

        return new RedirectResponse($to);
    }
}
