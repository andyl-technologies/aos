-- Retain the evidence that established each browser session.
ALTER TABLE sessions ADD COLUMN authentication_method TEXT NOT NULL DEFAULT 'legacy_local';
ALTER TABLE sessions ADD COLUMN authentication_provider TEXT;
