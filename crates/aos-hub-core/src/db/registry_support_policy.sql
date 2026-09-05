-- The committed release-train support policy travels with the index snapshot
-- like the registry readme: registry-wide current state read from the newest
-- indexed commit, stored as the policy's canonical JSON.
ALTER TABLE registry_index
  ADD COLUMN support_json TEXT;
