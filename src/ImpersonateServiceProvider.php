<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as Config;
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
            /** @var Config $config */
            $config = $app->make(Config::class);

            return new Impersonate($auth, $config, $app);
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
        Blade::directive('impersonating', static fn (string $expression): string => "<?php if (\\Thecyrilcril\\Impersonate\\ImpersonateServiceProvider::isImpersonating({$expression})): ?>");
        Blade::directive('endImpersonating', static fn (): string => '<?php endif; ?>');

        Blade::directive('canImpersonate', static fn (string $expression): string => "<?php if (\\Thecyrilcril\\Impersonate\\ImpersonateServiceProvider::canImpersonate({$expression})): ?>");
        Blade::directive('endCanImpersonate', static fn (): string => '<?php endif; ?>');

        Blade::directive('canBeImpersonated', static fn (string $expression): string => "<?php if (\\Thecyrilcril\\Impersonate\\ImpersonateServiceProvider::canBeImpersonated({$expression})): ?>");
        Blade::directive('endCanBeImpersonated', static fn (): string => '<?php endif; ?>');
    }

    /**
     * Backing check for the @impersonating directive.
     */
    public static function isImpersonating(?string $guard = null): bool
    {
        $manager = app(Impersonate::class);

        if (! $manager->isImpersonating()) {
            return false;
        }

        if ($guard === null) {
            return true;
        }

        /** @var Session $session */
        $session = app('session.store');

        return $session->get('impersonate.guard') === $guard;
    }

    /**
     * Backing check for the @canImpersonate directive.
     */
    public static function canImpersonate(?string $guard = null): bool
    {
        $user = app(AuthFactory::class)->guard($guard)->user();

        return $user !== null
            && method_exists($user, 'canImpersonate')
            && $user->canImpersonate();
    }

    /**
     * Backing check for the @canBeImpersonated directive.
     */
    public static function canBeImpersonated(Authenticatable $user, ?string $guard = null): bool
    {
        return method_exists($user, 'canBeImpersonated')
            && $user->canBeImpersonated();
    }

    private function configPath(): string
    {
        return __DIR__.'/../config/impersonate.php';
    }
}
