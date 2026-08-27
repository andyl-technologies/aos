-- Preserve every immutable publication independently of the policy head's
-- mutable resource-version fence. The original composite foreign key made a
-- second revision impossible because the first publication retained the
-- previous policy resource version.
ALTER TABLE placement_policy_publications
RENAME TO placement_policy_publications_legacy;

CREATE TABLE placement_policy_publications(
  publication_id KEYTEXT64 PRIMARY KEY,
  policy_revision_id KEYTEXT64 NOT NULL,
  policy_id KEYTEXT64 NOT NULL,
  revision_state KEYTEXT16 NOT NULL,
  policy_resource_version INTEGER NOT NULL,
  content_digest KEYTEXT128 NOT NULL,
  published_by KEYTEXT128 NOT NULL,
  published_at INTEGER NOT NULL,
  UNIQUE(policy_revision_id),
  FOREIGN KEY(policy_revision_id, policy_id, revision_state)
  REFERENCES placement_policy_revisions(id, policy_id, state),
  FOREIGN KEY(policy_id) REFERENCES placement_policy_heads(policy_id),
  CHECK(revision_state = 'published')
);

INSERT INTO placement_policy_publications
  (publication_id, policy_revision_id, policy_id, revision_state,
   policy_resource_version, content_digest, published_by, published_at)
SELECT publication_id, policy_revision_id, policy_id, revision_state,
       policy_resource_version, content_digest, published_by, published_at
FROM placement_policy_publications_legacy;

DROP TABLE placement_policy_publications_legacy;
