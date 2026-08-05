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

    /**
     * The target is typed as the guard-agnostic Authenticatable contract; in
     * practice it is usually your Eloquent User model. Consumers that need a
     * concrete Model must narrow with instanceof first.
     */
    public function __construct(
        public int|string $impersonatorId,
        public ?Authenticatable $target = null,
        public ?DateTimeInterface $occurredAt = null,
    ) {
        $this->occurredAt ??= new DateTimeImmutable;
    }
}
