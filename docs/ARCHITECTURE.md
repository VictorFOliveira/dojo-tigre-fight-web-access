# Architecture — DOJÔ TIGRE FIGHT

## Components

```text
Browser -> Web -> API -> PostgreSQL
                   |-> Asaas
                   |-> TotalPass Adapter
                   |-> Wellhub Adapter
                   |
                   <-> Tigre Fight Access -> SQLite
                              |
                              -> Hardware Adapter -> Catraca/Controladora
```

## Access decision

The Access agent is the operational boundary at the academy. A turnstile must not require an active internet connection for every passage.

1. Receive credential/event from hardware adapter.
2. Resolve cached person/credential.
3. Evaluate manual blocks and special access.
4. Evaluate enrollment/provider entitlement.
5. Evaluate financial/tolerance rule when applicable.
6. Evaluate modality, weekday and time window.
7. Produce `GRANTED` or `DENIED` plus a machine-readable reason.
8. Command hardware when granted.
9. Persist an immutable local event with UUID.
10. Queue the event for server synchronization.

## External providers

External benefit/payment providers are adapters and must not leak provider-specific concepts into the access decision engine.

```text
AccessEntitlementProvider
  InternalMembershipProvider
  TotalPassProvider
  WellhubProvider
```

TotalPass and Wellhub implementations must use official partner documentation and credentials. Until onboarding data is available, adapters may expose configuration/health capabilities but must not fabricate validation endpoints.

## Offline

Access keeps a minimum operational projection in SQLite: credentials, access policies, validity, schedules, manual blocks and synchronization metadata. Events use client-generated UUIDs and the API enforces uniqueness/idempotency.

A sync cycle has two directions: pull policy changes using revisions/cursors and push locally generated access events. Retries must be safe.

## Multi-academy readiness

The MVP serves one academy, but central domain records carry `academy_id`. Tenant isolation is enforced in application queries and authorization. This avoids a later destructive migration while keeping the deployment single-tenant initially.

## Security

- Secrets never reach the browser.
- Asaas/provider credentials are server-side secrets.
- Each Access installation has its own device identity/credential.
- Every access decision is auditable.
- Webhooks are authenticated/verified according to each provider's official mechanism.
- Sensitive logs are redacted.
- Biometric templates should remain in manufacturer equipment when feasible; biometric storage is not part of the initial MVP.

## Hardware

Hardware integration is intentionally abstract. Supported transport may ultimately be TCP/IP, serial, RS-232, RS-485, USB, HTTP or manufacturer SDK. No concrete protocol is implemented until the exact turnstile/controller model and official documentation are known.
