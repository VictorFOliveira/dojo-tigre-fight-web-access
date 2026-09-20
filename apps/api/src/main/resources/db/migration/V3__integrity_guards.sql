CREATE UNIQUE INDEX IF NOT EXISTS ux_memberships_one_open_per_modality
  ON memberships(academy_id,student_id,lower(modality))
  WHERE status IN ('PENDING','ACTIVE','PAUSED');

CREATE INDEX IF NOT EXISTS idx_credentials_student
  ON access_credentials(academy_id,student_id,active);

CREATE INDEX IF NOT EXISTS idx_notifications_pending
  ON notification_outbox(status,available_at)
  WHERE status='PENDING';
