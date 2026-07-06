<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Events;

use Illuminate\Contracts\Auth\Authenticatable;

final class TakenImpersonation
{
    public function __construct(
        public readonly Authenticatable $impersonator,
        public readonly Authenticatable $target,
    ) {}
}
