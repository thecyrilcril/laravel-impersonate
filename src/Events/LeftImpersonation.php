<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Events;

use DateTimeImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

final class LeftImpersonation
{
    use SerializesModels;

    public function __construct(
        public Authenticatable $impersonator,
        public Authenticatable $target,
        public ?DateTimeInterface $occurredAt = null,
    ) {
        $this->occurredAt ??= new DateTimeImmutable;
    }
}
