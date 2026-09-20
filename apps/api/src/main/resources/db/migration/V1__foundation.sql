CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS academies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE,
  legal_name text NOT NULL,
  trade_name text NOT NULL,
  status text NOT NULL DEFAULT 'TRIAL' CHECK (status IN ('TRIAL','ACTIVE','SUSPENDED','CANCELLED')),
  plan_code text NOT NULL DEFAULT 'STARTER',
  branding jsonb NOT NULL DEFAULT '{}'::jsonb,
  timezone text NOT NULL DEFAULT 'America/Fortaleza',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  academy_id uuid NOT NULL REFERENCES academies(id) ON DELETE CASCADE,
  name text NOT NULL,
  email text NOT NULL,
  password_hash text NOT NULL,
  role text NOT NULL CHECK (role IN ('OWNER','ADMIN','RECEPTION','COACH','FINANCE','STUDENT')),
  active boolean NOT NULL DEFAULT true,
  auth_version integer NOT NULL DEFAULT 1,
  mfa_enabled boolean NOT NULL DEFAULT false,
  mfa_secret_enc text,
  mfa_recovery_hashes jsonb NOT NULL DEFAULT '[]'::jsonb,
  mfa_enabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (academy_id,id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_academy_email ON users(academy_id,lower(email));
CREATE INDEX IF NOT EXISTS idx_users_academy_active ON users(academy_id,active,role);

CREATE TABLE IF NOT EXISTS students (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  academy_id uuid NOT NULL REFERENCES academies(id) ON DELETE CASCADE,
  portal_user_id uuid,
  name text NOT NULL,
  document text,
  email text,
  phone text,
  birth_date date,
  active boolean NOT NULL DEFAULT true,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (academy_id,id),
  FOREIGN KEY (academy_id,portal_user_id) REFERENCES users(academy_id,id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_students_academy_document ON students(academy_id,document) WHERE document IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_students_academy_active ON students(academy_id,active,name);

CREATE TABLE IF NOT EXISTS memberships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  academy_id uuid NOT NULL REFERENCES academies(id) ON DELETE CASCADE,
  student_id uuid NOT NULL,
  modality text NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('PENDING','ACTIVE','PAUSED','CANCELLED','EXPIRED')),
  starts_on date NOT NULL DEFAULT CURRENT_DATE,
  ends_on date,
  provider text,
  provider_member_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (academy_id,id),
  FOREIGN KEY (academy_id,student_id) REFERENCES students(academy_id,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_memberships_student ON memberships(academy_id,student_id,status);

CREATE TABLE IF NOT EXISTS audit_logs (
  id bigserial PRIMARY KEY,
  academy_id uuid REFERENCES academies(id) ON DELETE CASCADE,
  user_id uuid,
  action text NOT NULL,
  entity_type text,
  entity_id text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (academy_id,user_id) REFERENCES users(academy_id,id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_academy_time ON audit_logs(academy_id,created_at DESC);

CREATE TABLE IF NOT EXISTS academy_domains (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  academy_id uuid NOT NULL REFERENCES academies(id) ON DELETE CASCADE,
  domain text NOT NULL UNIQUE,
  kind text NOT NULL CHECK (kind IN ('CACTUS','CUSTOM')),
  verified boolean NOT NULL DEFAULT false,
  is_primary boolean NOT NULL DEFAULT false,
  verification_token text,
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_domains_academy ON academy_domains(academy_id,kind,verified);
CREATE UNIQUE INDEX IF NOT EXISTS ux_academy_primary_domain ON academy_domains(academy_id) WHERE is_primary=true;

CREATE TABLE IF NOT EXISTS privacy_settings (
  academy_id uuid PRIMARY KEY REFERENCES academies(id) ON DELETE CASCADE,
  contact_email text,
  dpo_name text,
  policy_url text,
  retention_notice text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS privacy_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  academy_id uuid NOT NULL REFERENCES academies(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,
  student_id uuid,
  type text NOT NULL CHECK (type IN ('ACCESS_EXPORT','CORRECTION','ANONYMIZATION','DELETION','PORTABILITY','SHARING_INFO','OPPOSITION','OTHER')),
  status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','IN_REVIEW','COMPLETED','REJECTED','CANCELED')),
  description text,
  response text,
  decision_reason text,
  reviewed_by uuid,
  reviewed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (academy_id,user_id) REFERENCES users(academy_id,id),
  FOREIGN KEY (academy_id,student_id) REFERENCES students(academy_id,id),
  FOREIGN KEY (academy_id,reviewed_by) REFERENCES users(academy_id,id)
);
CREATE INDEX IF NOT EXISTS idx_privacy_academy_status ON privacy_requests(academy_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_privacy_user ON privacy_requests(academy_id,user_id,created_at DESC);

CREATE TABLE IF NOT EXISTS privacy_consents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  academy_id uuid NOT NULL REFERENCES academies(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('PRIVACY_POLICY','TERMS_OF_USE','COMMUNICATION')),
  version text NOT NULL,
  accepted boolean NOT NULL,
  accepted_at timestamptz NOT NULL DEFAULT now(),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  FOREIGN KEY (academy_id,user_id) REFERENCES users(academy_id,id) ON DELETE CASCADE,
  UNIQUE (academy_id,user_id,kind,version)
);

CREATE TABLE IF NOT EXISTS access_agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  academy_id uuid NOT NULL REFERENCES academies(id) ON DELETE CASCADE,
  name text NOT NULL,
  key_hash char(64) NOT NULL,
  active boolean NOT NULL DEFAULT true,
  last_seen_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (academy_id,id)
);
CREATE INDEX IF NOT EXISTS idx_access_agents_academy ON access_agents(academy_id,active);

CREATE TABLE IF NOT EXISTS access_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  academy_id uuid NOT NULL REFERENCES academies(id) ON DELETE CASCADE,
  student_id uuid NOT NULL,
  credential_type text NOT NULL CHECK (credential_type IN ('QR','RFID','BIOMETRIC','PIN')),
  credential_hash char(64) NOT NULL,
  active boolean NOT NULL DEFAULT true,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (academy_id,id),
  FOREIGN KEY (academy_id,student_id) REFERENCES students(academy_id,id) ON DELETE CASCADE,
  UNIQUE (academy_id,credential_type,credential_hash)
);

CREATE TABLE IF NOT EXISTS access_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  academy_id uuid NOT NULL REFERENCES academies(id) ON DELETE CASCADE,
  agent_id uuid NOT NULL,
  student_id uuid,
  idempotency_key text NOT NULL,
  occurred_at timestamptz NOT NULL,
  decision text NOT NULL CHECK (decision IN ('ALLOW','DENY')),
  reason text NOT NULL,
  credential_type text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  received_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (academy_id,agent_id) REFERENCES access_agents(academy_id,id),
  FOREIGN KEY (academy_id,student_id) REFERENCES students(academy_id,id) ON DELETE SET NULL,
  UNIQUE (academy_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_access_events_academy_time ON access_events(academy_id,occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_events_student_time ON access_events(academy_id,student_id,occurred_at DESC);

CREATE TABLE IF NOT EXISTS platform_admins (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  active boolean NOT NULL DEFAULT true,
  auth_version integer NOT NULL DEFAULT 1,
  mfa_enabled boolean NOT NULL DEFAULT false,
  mfa_secret_enc text,
  mfa_recovery_hashes jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);

CREATE TABLE IF NOT EXISTS saas_plans (
  code text PRIMARY KEY,
  name text NOT NULL,
  monthly_price_cents integer NOT NULL CHECK (monthly_price_cents>=0),
  max_students integer,
  max_access_agents integer,
  active boolean NOT NULL DEFAULT true
);

INSERT INTO saas_plans(code,name,monthly_price_cents,max_students,max_access_agents) VALUES
('STARTER','Starter',9990,150,1),
('PRO','Pro',19990,500,3),
('ENTERPRISE','Enterprise',39990,NULL,NULL)
ON CONFLICT(code) DO NOTHING;
