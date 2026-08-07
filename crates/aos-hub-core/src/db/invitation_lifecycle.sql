-- Explicit invitation cancellation completes the lifecycle that the baseline
-- schema began with pending, accepted, and time-derived expired states.
ALTER TABLE invitations ADD COLUMN cancelled_at INTEGER;
ALTER TABLE invitations ADD COLUMN secret_enc LONGTEXT;

-- A separate live-key table makes the one-pending-invitation invariant
-- portable. UNIQUE partial indexes cannot exclude time-expired rows and are
-- not available consistently across SQLite, PostgreSQL, and MySQL. Terminal
-- transitions delete this row in the same transaction as their state stamp.
CREATE TABLE IF NOT EXISTS live_invitations(
  org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  invitation_id INTEGER NOT NULL UNIQUE REFERENCES invitations(id) ON DELETE CASCADE,
  PRIMARY KEY(org_id, email, scope_key)
);

-- Upgrade history may contain several unaccepted invitations for one tuple.
-- Terminalize every superseded row before backfilling exactly the newest one.
-- A newest-but-expired row is released by the first subsequent create's
-- clock-aware checked transaction. Historical secrets remain one-way hashes.
UPDATE invitations
SET cancelled_at = created_at
WHERE id IN (
  SELECT superseded_id FROM (
    SELECT older.id AS superseded_id
    FROM invitations older
    JOIN invitations newer
      ON newer.org_id = older.org_id
     AND newer.email = older.email
     AND newer.scope_key = older.scope_key
     AND (newer.created_at > older.created_at
          OR (newer.created_at = older.created_at AND newer.id > older.id))
    WHERE older.accepted_at IS NULL AND older.cancelled_at IS NULL
      AND newer.accepted_at IS NULL AND newer.cancelled_at IS NULL
  ) superseded
);

INSERT INTO live_invitations(org_id, email, scope_key, invitation_id)
SELECT org_id, email, scope_key, id
FROM invitations
WHERE accepted_at IS NULL AND cancelled_at IS NULL
ON CONFLICT(org_id, email, scope_key) DO NOTHING;
