-- Mirror scheduling does not own physical uncertainty. These per-object
-- originals and positive observations survive scheduler lease expiry and
-- retain the exact destination while a storage guard holds an unknown effect.
CREATE TABLE mirror_import_objects(
  job_id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE RESTRICT,
  original_digest KEYTEXT64 NOT NULL,
  original_json LONGTEXT NOT NULL,
  progress_json LONGTEXT,
  state KEYTEXT32 NOT NULL DEFAULT 'admitted',
  commit_digest KEYTEXT64,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  CHECK(length(job_id) = 64 AND length(original_digest) = 64),
  CHECK(state IN('admitted', 'staged_verified', 'published', 'committed')),
  CHECK(created_at > 0 AND updated_at >= created_at),
  CHECK((state = 'admitted' AND commit_digest IS NULL)
    OR (state IN('staged_verified', 'published') AND progress_json IS NOT NULL
        AND commit_digest IS NULL)
    OR (state = 'committed' AND progress_json IS NOT NULL
        AND commit_digest IS NOT NULL AND length(commit_digest) = 64))
);

CREATE INDEX mirror_import_registry_idx ON mirror_import_objects(registry_id, job_id);
