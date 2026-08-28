-- Preserve every immutable build event independently of the revision's
-- mutable build-version fence. The original composite foreign key made every
-- second build mutation impossible because the first event retained the
-- previous revision build version.
ALTER TABLE placement_policy_build_events
RENAME TO placement_policy_build_events_legacy;

CREATE TABLE placement_policy_build_events(
  event_id KEYTEXT64 PRIMARY KEY,
  policy_revision_id KEYTEXT64 NOT NULL,
  build_version INTEGER NOT NULL,
  revision_state KEYTEXT16 NOT NULL,
  mutation_kind KEYTEXT32 NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(policy_revision_id, build_version),
  FOREIGN KEY(policy_revision_id) REFERENCES placement_policy_revisions(id),
  CHECK(revision_state = 'building'),
  CHECK(mutation_kind IN('add_group', 'add_complete_member', 'add_shard_member'))
);
INSERT INTO placement_policy_build_events(
  event_id,
  policy_revision_id,
  build_version,
  revision_state,
  mutation_kind,
  created_at
)
SELECT
  event_id,
  policy_revision_id,
  build_version,
  revision_state,
  mutation_kind,
  created_at
FROM placement_policy_build_events_legacy;

DROP TABLE placement_policy_build_events_legacy;
