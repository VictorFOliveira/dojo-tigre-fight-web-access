# MVP

## Included

- Administrative authentication and roles.
- Academy-aware domain model (`academy_id`).
- Students, enrollment, modalities and modality-specific graduations.
- Credentials (RFID/card/code initially; extensible types).
- Monthly billing and Asaas integration/webhooks.
- Access policies: active/inactive, financial state, grace period, weekdays, time windows, modality, manual block/release, special access and permanent staff access.
- Access decision reason codes.
- Access events and attendance.
- Access device registration and health/last-sync state.
- TIGRE FIGHT ACCESS local SQLite cache, durable event queue and idempotent synchronization.
- Hardware adapter contract plus simulator for development. Real adapter only after manufacturer/model documentation is available.
- TotalPass adapter boundary and official integration when partner credentials/documentation are available.
- Wellhub adapter boundary and official integration when partner credentials/documentation are available.
- Dashboard and real-time access monitor.
- Audit log.

## Later

- Full SaaS billing and self-service tenant provisioning.
- Multiple branches per academy and advanced tenant administration.
- Facial recognition/biometrics beyond manufacturer-supported integrations.
- Dynamic QR credentials.
- Advanced class scheduling/capacity.
- Mobile synchronization with the existing Flutter application.
- Analytics/BI and advanced financial reports.
- Additional benefit providers.
- High-availability/multi-region infrastructure.

## First implementation milestones

1. Bootstrap Web/API/Access projects and CI.
2. PostgreSQL migrations and core domain.
3. Authentication + student/enrollment CRUD.
4. Access policy engine with unit tests.
5. Access simulator + SQLite offline cache/sync queue.
6. Web access monitor/dashboard.
7. Asaas billing integration.
8. TotalPass integration against official partner contract.
9. Wellhub integration after official partner onboarding contract is available.
10. Real turnstile adapter after hardware identification.
