<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Thecyrilcril\Impersonate\Concerns\ImpersonatesUsers;

/**
 * A second Authenticatable class whose auto-increment ids overlap with the
 * users table, used to exercise cross-class id-collision behaviour.
 *
 * @property int $id
 * @property string $name
 * @property string $email
 */
final class Admin extends Authenticatable implements AuthenticatableContract
{
    use ImpersonatesUsers;

    protected $table = 'admins';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];
}
