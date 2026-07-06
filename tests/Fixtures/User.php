<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Thecyrilcril\Impersonate\Concerns\ImpersonatesUsers;

/**
 * @property int $id
 * @property string $name
 * @property string $email
 * @property bool $may_impersonate
 * @property bool $protected
 * @property string $remember_token
 */
final class User extends Authenticatable implements AuthenticatableContract
{
    use ImpersonatesUsers;

    /**
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'may_impersonate',
        'protected',
        'remember_token',
    ];

    /**
     * @var array<string, string>
     */
    protected $casts = [
        'may_impersonate' => 'boolean',
        'protected' => 'boolean',
    ];

    public function canImpersonate(): bool
    {
        return $this->may_impersonate;
    }

    public function canBeImpersonated(): bool
    {
        return ! $this->protected;
    }
}
