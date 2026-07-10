# Changelog

All notable changes to `laravel-impersonate` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v1.0.0 - 2026-07-10

First stable release.

### Added

- `Impersonate` manager with guard-aware `take()` / `leave()` that restores
  the impersonator on their original guard.
- `ImpersonatesUsers` trait: `impersonate()`, `leaveImpersonation()`,
  `isImpersonated()`, and the `canImpersonate()` / `canBeImpersonated()`
  authorization hooks.
- State API: `isImpersonating()`, `isActive()`, `getImpersonatorId()`,
  `getImpersonator()`, `impersonatedUser()`, `impersonatingOnGuard()`,
  `restoreGuard()`.
- TTL support: `startedAt()`, `hasExpired()`, `minutesRemaining()`, and the
  `HandleImpersonationSession` middleware (alias `impersonate.session`) that
  auto-ends expired impersonations and cleans up sessions whose impersonated
  user was deleted, flashing `impersonate.status` (`expired` /
  `target-missing`).
- `ProtectFromImpersonation` middleware (alias `impersonate.protect`) that
  returns 403 while impersonating.
- Events with queue-safe `SerializesModels` payloads and an `occurredAt`
  timestamp: `TakenImpersonation`, `LeftImpersonation`, and
  `OrphanedImpersonationLeft` (fired when the impersonator was deleted
  mid-session so the leave stays auditable).
- Blade directives: `@impersonating` (optional guard), `@canImpersonate`
  (optional guard), `@canBeImpersonated($user)`.
- Security hardening: session-id regeneration on take and leave (fixation
  defense), quiet swaps (no Login/Logout events, remember tokens never
  touched), fail-closed guard detection, session-guard-only enforcement,
  nested and self impersonation blocked, recycled-id defense via class check
  plus opt-in `getImpersonationFingerprint()`, and per-session atomic locking
  of take/leave when the cache store supports locks.
