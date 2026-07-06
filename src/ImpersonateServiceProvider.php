<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\ServiceProvider;
use Thecyrilcril\Impersonate\Http\Middleware\ProtectFromImpersonation;

final class ImpersonateServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom($this->configPath(), 'impersonate');

        $this->app->singleton(Impersonate::class, static function ($app): Impersonate {
            /** @var AuthFactory $auth */
            $auth = $app->make(AuthFactory::class);
            /** @var Session $session */
            $session = $app->make('session.store');
            /** @var Dispatcher $events */
            $events = $app->make(Dispatcher::class);
            /** @var Config $config */
            $config = $app->make(Config::class);

            return new Impersonate($auth, $session, $events, $config);
        });

        $this->app->alias(Impersonate::class, 'impersonate');
    }

    public function boot(): void
    {
        $this->publishes([
            $this->configPath() => $this->app->configPath('impersonate.php'),
        ], 'impersonate-config');

        $this->registerMiddlewareAlias();
        $this->registerBladeDirectives();
    }

    private function registerMiddlewareAlias(): void
    {
        /** @var Router $router */
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('impersonate.protect', ProtectFromImpersonation::class);
    }

    private function registerBladeDirectives(): void
    {
        Blade::if('impersonating', static function (?string $guard = null): bool {
            $manager = app(Impersonate::class);

            if (! $manager->isImpersonating()) {
                return false;
            }

            if ($guard === null) {
                return true;
            }

            return app('session.store')->get('impersonate.guard') === $guard;
        });

        Blade::if('canImpersonate', static function (?string $guard = null): bool {
            $user = app(AuthFactory::class)->guard($guard)->user();

            return $user !== null
                && method_exists($user, 'canImpersonate')
                && $user->canImpersonate();
        });

        Blade::if('canBeImpersonated', static function (Authenticatable $user, ?string $guard = null): bool {
            return method_exists($user, 'canBeImpersonated')
                && $user->canBeImpersonated();
        });
    }

    private function configPath(): string
    {
        return __DIR__.'/../config/impersonate.php';
    }
}
