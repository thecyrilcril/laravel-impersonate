<?php

declare(strict_types=1);

namespace Thecyrilcril\Impersonate\Events;

use DateTimeImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

/**
 * Dispatched when an impersonation session ends but the impersonator no
 * longer exists (deleted mid-impersonation), so the leave stays auditable
 * even though a LeftImpersonation event cannot be built.
 */
final class OrphanedImpersonationLeft
{
    use SerializesModels;

    public function __construct(
        public int|string $impersonatorId,
        public ?Authenticatable $target = null,
        public ?DateTimeInterface $occurredAt = null,
    ) {
        $this->occurredAt ??= new DateTimeImmutable;
    }
}
