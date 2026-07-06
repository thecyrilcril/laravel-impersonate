<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

final class TakenImpersonation
{
    use SerializesModels;

    public function __construct(
        public Authenticatable $impersonator,
        public Authenticatable $target,
    ) {}
}
