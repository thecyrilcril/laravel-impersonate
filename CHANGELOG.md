# Changelog

All notable changes to `laravel-impersonate` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v1.1.0 - 2026-08-05

### Added

- `ImpersonatesUsers::isImpersonator()` — true when this user is the
  impersonator of the active impersonation (matched by class and id). Note
  that during impersonation the authenticated user is the *target*, so call
  it on a model you hold directly, and keep using the manager's
  `isImpersonating()` for "is this session impersonating at all" checks
  (e.g. anti-chaining guards).
- `Impersonate::getImpersonatorType()` — the impersonator's model class as
  captured at take-time, or null when not impersonating.
- README: guidance on the direction of `isImpersonated()` /
  `isImpersonator()`, anti-chaining via the manager, why `#[\Override]`
  fatals on the trait hooks, narrowing the events' `Authenticatable` payloads
  for concrete-Model consumers, and avoiding double listener registration
  with Laravel's event discovery.

### Fixed

- `ImpersonatesUsers::isImpersonated()` now matches the documented behaviour
  ("is impersonating **this user**") by comparing against the impersonated
  user's class and id. Previously it returned true for *every* user except
  the impersonator while an impersonation was active, and false for a target
  whose id collided with the impersonator's across different Authenticatable
  classes.

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
