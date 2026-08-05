<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Events;

use DateTimeImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

final class TakenImpersonation
{
    use SerializesModels;

    /**
     * Both users are typed as the guard-agnostic Authenticatable contract; in
     * practice they are usually your Eloquent User model. Consumers that need
     * a concrete Model (e.g. activitylog's causedBy()/performedOn()) must
     * narrow with instanceof first.
     */
    public function __construct(
        public Authenticatable $impersonator,
        public Authenticatable $target,
        public ?DateTimeInterface $occurredAt = null,
    ) {
        $this->occurredAt ??= new DateTimeImmutable;
    }
}
