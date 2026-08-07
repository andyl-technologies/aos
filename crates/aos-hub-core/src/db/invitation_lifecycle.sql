-- Explicit invitation cancellation completes the lifecycle that the baseline
-- schema began with pending, accepted, and time-derived expired states.
ALTER TABLE invitations ADD COLUMN cancelled_at INTEGER;

CREATE INDEX invitations_org_created ON invitations(org_id, created_at DESC, id DESC);
