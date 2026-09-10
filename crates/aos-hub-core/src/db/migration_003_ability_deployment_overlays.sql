-- Admin-enrolled identities allowed to submit private, bounded deployment state.
CREATE TABLE ability_deployment_reporters(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  deployment KEYTEXT128 NOT NULL,
  principal_kind KEYTEXT32 NOT NULL,
  principal_id INTEGER NOT NULL,
  principal_ref TEXT NOT NULL,
  active INTEGER NOT NULL,
  resource_version INTEGER NOT NULL,
  current_sequence INTEGER NOT NULL DEFAULT 0,
  last_mutation_plan_id KEYTEXT64 NOT NULL,
  registry_commit KEYTEXT64,
  package_name KEYTEXT128,
  package_version KEYTEXT64,
  platform KEYTEXT64,
  manifest_sha256 KEYTEXT128,
  package_digest KEYTEXT128,
  canonical_json BLOB,
  reported_at INTEGER,
  received_at INTEGER,
  expires_at INTEGER,
  PRIMARY KEY(registry_id, deployment),
  CHECK(principal_kind IN('user', 'service_account')),
  CHECK(active IN(0, 1)),
  CHECK(resource_version > 0),
  CHECK(current_sequence >= 0),
  CHECK(
    (current_sequence = 0
      AND registry_commit IS NULL AND package_name IS NULL AND package_version IS NULL
      AND platform IS NULL AND manifest_sha256 IS NULL AND package_digest IS NULL
      AND canonical_json IS NULL AND reported_at IS NULL AND received_at IS NULL
      AND expires_at IS NULL)
    OR
    (current_sequence > 0
      AND registry_commit IS NOT NULL AND package_name IS NOT NULL
      AND package_version IS NOT NULL AND platform IS NOT NULL
      AND manifest_sha256 IS NOT NULL AND package_digest IS NOT NULL
      AND canonical_json IS NOT NULL AND reported_at IS NOT NULL
      AND received_at IS NOT NULL AND expires_at > received_at)
  ),
  CHECK(canonical_json IS NULL OR (length(canonical_json) > 0 AND length(canonical_json) <= 1048576))
);

CREATE INDEX ability_deployment_overlay_anchor
ON ability_deployment_reporters(
  registry_id, registry_commit, package_name, package_version, platform, active, expires_at
);
