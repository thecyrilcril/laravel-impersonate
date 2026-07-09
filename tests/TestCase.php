<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;
use Thecyrilcril\Impersonate\ImpersonateServiceProvider;
use Thecyrilcril\Impersonate\Tests\Fixtures\User;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('users', static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password')->nullable();
            $table->boolean('may_impersonate')->default(true);
            $table->boolean('protected')->default(false);
            $table->string('fingerprint')->nullable();
            $table->rememberToken();
            $table->timestamps();
        });
    }

    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            ImpersonateServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $config = $app['config'];

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $config->set('auth.providers.users.model', User::class);

        // A second guard backed by the same provider, used to exercise
        // guard-aware take/leave behaviour.
        $config->set('auth.guards.admin', [
            'driver' => 'session',
            'provider' => 'users',
        ]);
    }

    protected function makeUser(array $attributes = []): User
    {
        return User::query()->create(array_merge([
            'name' => 'User '.uniqid(),
            'email' => uniqid().'@example.com',
            'password' => bcrypt('password'),
            'may_impersonate' => true,
            'protected' => false,
            'remember_token' => 'original-token',
        ], $attributes));
    }
}
