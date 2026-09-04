-- A persisted generation distinguishes registries that have completed a
-- documentation-aware full index from legacy snapshots whose empty
-- documentation projection would otherwise look complete.
ALTER TABLE registry_index
  ADD COLUMN documentation_projection_generation INTEGER NOT NULL DEFAULT 0;
