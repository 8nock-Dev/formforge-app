CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, name TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expiry ON password_reset_tokens(expires_at);
CREATE TABLE IF NOT EXISTS forms (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL, token_prefix TEXT NOT NULL,
  schema JSONB NOT NULL DEFAULT '[]', allowed_origins JSONB NOT NULL DEFAULT '[]',
  redirect_url TEXT, notify_email TEXT, webhook_url TEXT, webhook_secret TEXT,
  retention_days INTEGER NOT NULL DEFAULT 365 CHECK (retention_days BETWEEN 1 AND 3650),
  is_active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS submissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), form_id UUID NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
  data JSONB NOT NULL, is_spam BOOLEAN NOT NULL DEFAULT false, is_read BOOLEAN NOT NULL DEFAULT false,
  source_ip_hash TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), submission_id UUID NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
  webhook_url TEXT NOT NULL, payload JSONB NOT NULL, attempt INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending', next_attempt_at TIMESTAMPTZ DEFAULT NOW(),
  last_error TEXT, delivered_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_forms_user ON forms(user_id);
CREATE INDEX IF NOT EXISTS idx_submissions_form_time ON submissions(form_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_due ON webhook_deliveries(next_attempt_at) WHERE status='pending';
