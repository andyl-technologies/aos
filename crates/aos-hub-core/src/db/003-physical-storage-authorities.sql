-- Immutable physical domains prepare external S3 coordination. No existing
-- binding or inventory is adopted, and no destructive capability is enabled.
CREATE TABLE physical_storage_authorities(
  authority_id KEYTEXT64 PRIMARY KEY,
  guard_namespace_id KEYTEXT255 NOT NULL,
  specification_json LONGTEXT NOT NULL,
  specification_digest KEYTEXT64 NOT NULL,
  creation_plan_id KEYTEXT64 NOT NULL REFERENCES topology_plans(plan_id) ON DELETE RESTRICT,
  created_at INTEGER NOT NULL,
  UNIQUE(authority_id, guard_namespace_id)
);

-- Exact addresses remain reserved after revocation; approval never moves an
-- alias between authorities or infers equivalence by DNS, ETag, or credentials.
CREATE TABLE physical_storage_aliases(
  alias_id KEYTEXT64 PRIMARY KEY,
  authority_id KEYTEXT64 NOT NULL REFERENCES physical_storage_authorities(authority_id) ON DELETE RESTRICT,
  canonical_alias_digest KEYTEXT64 NOT NULL UNIQUE,
  specification_json LONGTEXT NOT NULL,
  approval_plan_id KEYTEXT64 NOT NULL REFERENCES topology_plans(plan_id) ON DELETE RESTRICT,
  approved_at INTEGER NOT NULL,
  UNIQUE(alias_id, authority_id)
);

CREATE TABLE binding_storage_authority_revisions(
  association_id KEYTEXT64 PRIMARY KEY,
  authority_id KEYTEXT64 NOT NULL,
  alias_id KEYTEXT64 NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  binding_prefix KEYTEXT512 NOT NULL,
  specification_json LONGTEXT NOT NULL,
  approval_plan_id KEYTEXT64 NOT NULL REFERENCES topology_plans(plan_id) ON DELETE RESTRICT,
  approved_at INTEGER NOT NULL,
  UNIQUE(binding_id, binding_resource_version, binding_write_revision),
  UNIQUE(association_id, authority_id),
  FOREIGN KEY(alias_id, authority_id) REFERENCES physical_storage_aliases(alias_id, authority_id) ON DELETE RESTRICT,
  FOREIGN KEY(binding_id, binding_write_revision) REFERENCES binding_write_revisions(binding_id, revision) ON DELETE RESTRICT,
  CHECK(binding_resource_version > 0 AND binding_write_revision > 0)
);

CREATE TABLE storage_authority_attestations(
  attestation_id KEYTEXT64 PRIMARY KEY,
  authority_id KEYTEXT64 NOT NULL REFERENCES physical_storage_authorities(authority_id) ON DELETE RESTRICT,
  provider_mode KEYTEXT32 NOT NULL DEFAULT 'nonversioned_s3',
  managed_prefix KEYTEXT512 NOT NULL,
  specification_json LONGTEXT NOT NULL,
  specification_digest KEYTEXT64 NOT NULL,
  approval_plan_id KEYTEXT64 NOT NULL REFERENCES topology_plans(plan_id) ON DELETE RESTRICT,
  valid_until INTEGER NOT NULL,
  approved_at INTEGER NOT NULL,
  UNIQUE(attestation_id, authority_id),
  CHECK(provider_mode = 'nonversioned_s3'),
  CHECK(valid_until > approved_at)
);

CREATE TABLE storage_authority_credential_members(
  attestation_id KEYTEXT64 NOT NULL,
  authority_id KEYTEXT64 NOT NULL,
  association_id KEYTEXT64 NOT NULL,
  binding_id INTEGER NOT NULL,
  purpose KEYTEXT16 NOT NULL,
  generation INTEGER NOT NULL,
  PRIMARY KEY(attestation_id, association_id, purpose),
  FOREIGN KEY(attestation_id, authority_id) REFERENCES storage_authority_attestations(attestation_id, authority_id) ON DELETE RESTRICT,
  FOREIGN KEY(association_id, authority_id) REFERENCES binding_storage_authority_revisions(association_id, authority_id) ON DELETE RESTRICT,
  FOREIGN KEY(binding_id, purpose, generation) REFERENCES binding_credential_revisions(binding_id, purpose, generation) ON DELETE RESTRICT,
  CHECK(generation > 0),
  CHECK(purpose IN('read', 'write', 'delete', 'list', 'presign'))
);

CREATE TABLE storage_authority_admission_revisions(
  authority_id KEYTEXT64 NOT NULL REFERENCES physical_storage_authorities(authority_id) ON DELETE RESTRICT,
  generation INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  attestation_id KEYTEXT64,
  specification_json LONGTEXT NOT NULL,
  specification_digest KEYTEXT64 NOT NULL,
  approval_plan_id KEYTEXT64 NOT NULL REFERENCES topology_plans(plan_id) ON DELETE RESTRICT,
  approved_at INTEGER NOT NULL,
  PRIMARY KEY(authority_id, generation),
  FOREIGN KEY(attestation_id, authority_id) REFERENCES storage_authority_attestations(attestation_id, authority_id) ON DELETE RESTRICT,
  CHECK(generation > 0),
  CHECK(state IN('admitted', 'blocked', 'retired')),
  CHECK((state = 'admitted' AND attestation_id IS NOT NULL) OR state <> 'admitted')
);

CREATE TABLE storage_authority_admission_heads(
  authority_id KEYTEXT64 PRIMARY KEY REFERENCES physical_storage_authorities(authority_id) ON DELETE RESTRICT,
  desired_generation INTEGER,
  acknowledged_generation INTEGER,
  acknowledged_digest KEYTEXT64,
  resource_version INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY(authority_id, desired_generation) REFERENCES storage_authority_admission_revisions(authority_id, generation) ON DELETE RESTRICT,
  CHECK(resource_version > 0),
  CHECK((acknowledged_generation IS NULL AND acknowledged_digest IS NULL)
    OR (acknowledged_generation > 0 AND acknowledged_digest IS NOT NULL))
);

-- The immutable desired revision is also the exact control delivery payload.
-- This outbox prepares delivery; only the future authenticated adapter may
-- reconcile a fresh remote watermark. A SQL acknowledgement alone admits no I/O.
CREATE TABLE storage_authority_control_requests(
  authority_id KEYTEXT64 NOT NULL,
  generation INTEGER NOT NULL,
  request_id KEYTEXT64 NOT NULL UNIQUE,
  specification_digest KEYTEXT64 NOT NULL,
  acknowledged_at INTEGER,
  PRIMARY KEY(authority_id, generation),
  FOREIGN KEY(authority_id, generation) REFERENCES storage_authority_admission_revisions(authority_id, generation) ON DELETE RESTRICT
);
