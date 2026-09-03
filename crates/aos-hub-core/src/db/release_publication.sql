-- Release publication continuity is system-of-record state. Generic registry
-- publications retain physical object evidence; these rows bind those exact
-- publications into the staging, qualification, production, timestamp, and
-- channel release protocol.
CREATE TABLE release_bundles(
  bundle_digest KEYTEXT128 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  release_id KEYTEXT128 NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  registry_base_commit KEYTEXT128 NOT NULL,
  staging_deployment_id KEYTEXT128 NOT NULL,
  production_deployment_id KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(registry_id, release_id),
  UNIQUE(registry_id, manifest_digest),
  UNIQUE(bundle_digest, registry_id)
);

CREATE TABLE release_bundle_publications(
  bundle_digest KEYTEXT128 NOT NULL REFERENCES release_bundles(bundle_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  registry_id INTEGER NOT NULL,
  environment KEYTEXT16 NOT NULL,
  publication_id KEYTEXT64 NOT NULL,
  deployment_id KEYTEXT128 NOT NULL,
  receipt_digest KEYTEXT128 NOT NULL,
  receipt_json TEXT NOT NULL,
  staging_receipt_digest KEYTEXT128,
  committed_at INTEGER NOT NULL,
  PRIMARY KEY(bundle_digest, environment),
  UNIQUE(publication_id),
  UNIQUE(receipt_digest),
  FOREIGN KEY(bundle_digest, registry_id)
    REFERENCES release_bundles(bundle_digest, registry_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(publication_id, registry_id)
    REFERENCES registry_publications(publication_id, registry_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CHECK(environment IN('staging', 'production')),
  CHECK((environment = 'staging' AND staging_receipt_digest IS NULL)
    OR (environment = 'production' AND staging_receipt_digest IS NOT NULL))
);

CREATE TABLE release_qualifications(
  bundle_digest KEYTEXT128 PRIMARY KEY REFERENCES release_bundles(bundle_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  staging_receipt_digest KEYTEXT128 NOT NULL REFERENCES release_bundle_publications(receipt_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  qualification_digest KEYTEXT128 NOT NULL UNIQUE,
  receipt_json TEXT NOT NULL,
  qualified_at INTEGER NOT NULL
);

CREATE TABLE release_promotions(
  bundle_digest KEYTEXT128 PRIMARY KEY REFERENCES release_bundles(bundle_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  staging_receipt_digest KEYTEXT128 NOT NULL REFERENCES release_bundle_publications(receipt_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  qualification_digest KEYTEXT128 NOT NULL REFERENCES release_qualifications(qualification_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  production_receipt_digest KEYTEXT128 NOT NULL REFERENCES release_bundle_publications(receipt_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  promoted_at INTEGER NOT NULL,
  UNIQUE(production_receipt_digest)
);

CREATE TABLE release_timestamp_publications(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  snapshot_digest KEYTEXT128 NOT NULL,
  snapshot_version INTEGER NOT NULL,
  timestamp_version INTEGER NOT NULL,
  timestamp_digest KEYTEXT128 NOT NULL UNIQUE,
  publication_id KEYTEXT64 NOT NULL,
  committed_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, timestamp_version),
  UNIQUE(registry_id, snapshot_digest, timestamp_version),
  FOREIGN KEY(publication_id, registry_id)
    REFERENCES registry_publications(publication_id, registry_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CHECK(snapshot_version > 0),
  CHECK(timestamp_version > 0)
);

CREATE TABLE release_channel_operations(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  channel KEYTEXT16 NOT NULL,
  prior_generation INTEGER NOT NULL,
  new_generation INTEGER NOT NULL,
  first_partition INTEGER NOT NULL,
  last_partition INTEGER NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  production_receipt_digest KEYTEXT128 NOT NULL REFERENCES release_bundle_publications(receipt_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  operation_digest KEYTEXT128 NOT NULL UNIQUE,
  receipt_json TEXT NOT NULL,
  committed_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, channel, new_generation),
  CHECK(channel IN('edge', 'candidate', 'stable')),
  CHECK(prior_generation >= 0),
  CHECK(new_generation = prior_generation + 1),
  CHECK(first_partition >= 0 AND first_partition <= last_partition AND last_partition <= 255)
);

CREATE INDEX release_bundle_publications_registry_idx
  ON release_bundle_publications(registry_id, environment, committed_at);
CREATE INDEX release_channel_operations_manifest_idx
  ON release_channel_operations(registry_id, manifest_digest);

