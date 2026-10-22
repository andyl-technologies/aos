-- Bind passkey registration to one recently authenticated browser session.
ALTER TABLE sessions ADD COLUMN reauthentication_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE webauthn_challenges ADD COLUMN session_id_hash TEXT;
ALTER TABLE webauthn_challenges ADD COLUMN reauthentication_generation INTEGER;
