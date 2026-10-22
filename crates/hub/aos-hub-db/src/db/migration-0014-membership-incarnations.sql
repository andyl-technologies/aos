ALTER TABLE memberships ADD COLUMN incarnation_id KEYTEXT32;

CREATE UNIQUE INDEX memberships_incarnation_idx
ON memberships(incarnation_id);
