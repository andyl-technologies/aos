-- First stable production schema. This baseline is immutable after deployment.
-- Append new migrations for every subsequent schema change; never replay a reset.

CREATE TABLE hub_schema_identity(
  identity TEXT PRIMARY KEY
);

CREATE TABLE egress_request_nonces(
  nonce KEYTEXT128 PRIMARY KEY,
  request_digest KEYTEXT128 NOT NULL,
  accepted_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  CHECK(expires_at > accepted_at)
);

CREATE TABLE orgs(
  id INTEGER PRIMARY KEY,
  stable_id KEYTEXT64 NOT NULL UNIQUE,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  deleted_at INTEGER,
  purge_after INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER,
  creation_plan_id KEYTEXT64,
  mutation_plan_id KEYTEXT64
);

CREATE UNIQUE INDEX orgs_creation_plan_idx ON orgs(creation_plan_id);

CREATE TABLE users(
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT,
  created_at INTEGER NOT NULL,
  deleted_at INTEGER,
  password_hash TEXT
);

CREATE TABLE magic_links(
  token_hash TEXT PRIMARY KEY, -- SHA-256 hex of the link secret
  email TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE TABLE audit_log(
  id INTEGER PRIMARY KEY,
  outbox_event_id KEYTEXT64 UNIQUE,
  change_id KEYTEXT64, -- ties to a changeset(nullable)
  actor_kind TEXT NOT NULL, -- user|service_account|key|system
  actor_id INTEGER, -- principal row id, when applicable
  actor_label TEXT NOT NULL, -- human string(email, sa:org/name, fpr, system)
  action TEXT NOT NULL, -- the mutating verb
  scope TEXT NOT NULL, -- immutable authorization/event subject key
  result_commit TEXT, -- resulting git commit hash(surface ops)
  result_tag TEXT, -- resulting git tag hash(surface ops)
  detail TEXT, -- free-form(often compact JSON)
  created_at INTEGER NOT NULL
);

CREATE INDEX audit_log_scope_idx ON audit_log(scope,
  id);

CREATE INDEX audit_log_change_idx ON audit_log(change_id);

CREATE TABLE change_requests(
  change_id KEYTEXT64 PRIMARY KEY, -- UUID v4
  actor_kind TEXT NOT NULL,
  actor_id INTEGER,
  actor_label TEXT NOT NULL,
  scope TEXT NOT NULL,
  status TEXT NOT NULL, -- draft|applied|reverted
  summary TEXT,
  created_at INTEGER NOT NULL,
  applied_at INTEGER,
  reverted_by_change_id KEYTEXT64,
  git_ref TEXT,
  git_commit TEXT,
  title TEXT,
  body TEXT,
  closed_at INTEGER
);

CREATE INDEX change_requests_scope_idx ON change_requests(
  scope,
  created_at
);

CREATE TABLE instance_config(config_key TEXT PRIMARY KEY,
value TEXT NOT NULL);

CREATE TABLE webauthn_challenges(
  challenge TEXT PRIMARY KEY, -- base64url random challenge
  user_id INTEGER, -- registering user, or NULL(usernameless assertion)
  kind TEXT NOT NULL, -- 'registration' | 'assertion'
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE rate_limits(
  class TEXT NOT NULL,
  key TEXT NOT NULL,
  window INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY(class, key, window)
);

CREATE TABLE image_snapshots(
  digest KEYTEXT64 PRIMARY KEY,
  byte_size INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL DEFAULT('live'),
  created_at INTEGER NOT NULL,
  CHECK(length(digest) = 64 AND byte_size > 0),
  CHECK(state IN('live', 'collectible'))
);

CREATE TABLE retention_leases(
  id KEYTEXT64 PRIMARY KEY,
  manual_retention_root_id KEYTEXT64 NOT NULL,
  begins_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  renewed_from_lease_id KEYTEXT64,
  state KEYTEXT16 NOT NULL,
  renewed_by KEYTEXT128 NOT NULL,
  renewed_at INTEGER NOT NULL,
  revoked_by KEYTEXT128,
  revoked_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK(expires_at > begins_at),
  CHECK(state IN('active', 'superseded', 'revoked')),
  CHECK((state = 'revoked' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL)
OR(state IN('active', 'superseded') AND revoked_by IS NULL AND revoked_at IS NULL)),
  UNIQUE(id, manual_retention_root_id),
  FOREIGN KEY(renewed_from_lease_id, manual_retention_root_id)
  REFERENCES retention_leases(id, manual_retention_root_id)
);

CREATE TABLE topology_plans(
  plan_id KEYTEXT64 PRIMARY KEY,
  plan_kind KEYTEXT64 NOT NULL,
  actor_kind KEYTEXT32 NOT NULL,
  actor_id INTEGER,
  actor_label TEXT NOT NULL,
  scope KEYTEXT255 NOT NULL,
  input_versions_json LONGTEXT NOT NULL,
  effects_json LONGTEXT NOT NULL,
  warnings_json LONGTEXT NOT NULL,
  confirmation_hash KEYTEXT128,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  applied_at INTEGER,
  request_idempotency_key KEYTEXT128,
  request_digest KEYTEXT128,
  apply_idempotency_key KEYTEXT128,
  apply_result_json LONGTEXT,
  CHECK(expires_at > created_at),
  CHECK(actor_kind IN('user', 'service_account', 'key', 'system'))
);

CREATE INDEX topology_plans_scope_idx ON topology_plans(scope,
  created_at);

CREATE TABLE route_url_reservations(
  id KEYTEXT64 PRIMARY KEY,
  digest_scheme KEYTEXT32 NOT NULL,
  reservation_key_version INTEGER NOT NULL,
  reservation_digest BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(reservation_key_version, reservation_digest),
  CHECK(digest_scheme = 'hmac_sha256_v1'),
  CHECK(length(reservation_digest) = 32)
);

CREATE TABLE route_replacements(
  successor_route_id KEYTEXT64 PRIMARY KEY,
  predecessor_route_id KEYTEXT64 NOT NULL UNIQUE,
  predecessor_resource_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  CHECK(successor_route_id <> predecessor_route_id),
  CHECK(predecessor_resource_version > 0)
);

CREATE TABLE delivery_attestation_nonces(
  route_id KEYTEXT64 NOT NULL,
  route_configuration_digest KEYTEXT128 NOT NULL,
  nonce_digest KEYTEXT128 NOT NULL,
  expires_at INTEGER NOT NULL,
  accepted_at INTEGER NOT NULL,
  PRIMARY KEY(route_id, route_configuration_digest, nonce_digest),
  CHECK(length(route_configuration_digest) = 64),
  CHECK(length(nonce_digest) = 64),
  CHECK(expires_at >= accepted_at),
  CHECK(expires_at <= accepted_at + 35)
);

CREATE TABLE write_recovery_cursors(
  recovery_kind KEYTEXT16 PRIMARY KEY,
  after_expires_at INTEGER NOT NULL,
  after_ticket_id KEYTEXT64 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  CHECK(recovery_kind = 'cache'),
  CHECK(resource_version > 0)
);

CREATE TABLE consumer_scope_grant_events(
  event_id KEYTEXT64 PRIMARY KEY,
  resource_kind KEYTEXT32 NOT NULL,
  resource_stable_id KEYTEXT64 NOT NULL,
  resource_generation_key INTEGER NOT NULL,
  consumer_scope_key KEYTEXT64 NOT NULL,
  grant_generation INTEGER NOT NULL,
  transition KEYTEXT16 NOT NULL,
  previous_state KEYTEXT16,
  resulting_state KEYTEXT16 NOT NULL,
  actor_id KEYTEXT128 NOT NULL,
  occurred_at INTEGER NOT NULL,
  request_id KEYTEXT128 NOT NULL,
  CHECK(resource_kind IN('binding', 'network_policy', 'endpoint', 'gateway')),
  CHECK(transition IN('granted', 'revoked', 'regranted')),
  CHECK(resulting_state IN('active', 'revoked')),
  CHECK(grant_generation > 0)
);

CREATE TABLE cache_gc_epoch_assertions(
  mutation_id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL,
  expected_epoch INTEGER NOT NULL,
  resulting_epoch INTEGER NOT NULL,
  epoch_owner_token KEYTEXT64 NOT NULL,
  mutation_kind KEYTEXT32 NOT NULL,
  ok INTEGER NOT NULL,
  asserted_at INTEGER NOT NULL,
  UNIQUE(mutation_id, cache_id),
  CHECK(resulting_epoch = expected_epoch + 1),
  CHECK(mutation_kind IN('root', 'object_graph', 'inventory', 'topology', 'policy', 'fence')),
  CHECK(ok = 1)
);

CREATE TABLE worker_job_executions(
  operation_id KEYTEXT64 PRIMARY KEY,
  job_kind KEYTEXT64 NOT NULL,
  payload_digest KEYTEXT64 NOT NULL,
  state KEYTEXT16 NOT NULL DEFAULT 'pending',
  claim_token KEYTEXT64,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  lease_expires_at INTEGER,
  last_error LONGTEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  completed_at INTEGER,
  CHECK(state IN('pending', 'running', 'completed')),
  CHECK(attempt_count >= 0),
  CHECK((state = 'pending' AND claim_token IS NULL AND lease_expires_at IS NULL
         AND completed_at IS NULL)
     OR (state = 'running' AND claim_token IS NOT NULL
         AND lease_expires_at IS NOT NULL AND completed_at IS NULL)
     OR (state = 'completed' AND claim_token IS NULL
         AND lease_expires_at IS NULL AND completed_at IS NOT NULL))
);

CREATE TABLE route_oci_capabilities(
  -- Route ids in an already-migrated MySQL v19 database use the historical
  -- VARCHAR representation, while new byte-exact keys use VARBINARY. The
  -- topology transaction explicitly deletes this side row with its route, so
  -- avoiding a cross-version textual FK preserves forward compatibility
  -- without weakening route mutation atomicity.
  route_id KEYTEXT64 PRIMARY KEY,
  serves_web INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  CHECK(serves_web IN(0, 1))
);

CREATE TABLE oci_phase5_upgrade_guard(
  id KEYTEXT16 PRIMARY KEY,
  marker INTEGER NOT NULL CHECK(marker = 0)
);

CREATE TABLE authorization_scopes(
  scope_key KEYTEXT64 PRIMARY KEY,
  kind KEYTEXT16 NOT NULL,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  parent_scope_key KEYTEXT64 REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  resource_stable_id KEYTEXT64 NOT NULL,
  owner_guard_version INTEGER NOT NULL DEFAULT 1,
  retired_at INTEGER,
  created_at INTEGER NOT NULL,
  UNIQUE(kind, resource_stable_id),
  UNIQUE(scope_key, org_id),
  UNIQUE(scope_key, kind, resource_stable_id, parent_scope_key),
  CHECK(kind IN('instance', 'organization', 'project', 'registry', 'binary_cache')),
  CHECK(owner_guard_version > 0),
  CHECK((kind = 'instance' AND scope_key = 'instance' AND org_id IS NULL
         AND resource_stable_id = 'instance' AND parent_scope_key IS NULL)
     OR (kind = 'organization' AND org_id IS NOT NULL
         AND scope_key = resource_stable_id
         AND parent_scope_key = 'instance')
     OR (kind IN('project', 'registry', 'binary_cache')
         AND scope_key = resource_stable_id AND parent_scope_key IS NOT NULL)),
  CHECK(kind = 'instance' OR (
    LENGTH(scope_key) = CASE kind
      WHEN 'organization' THEN 36 WHEN 'project' THEN 40
      WHEN 'registry' THEN 41 WHEN 'binary_cache' THEN 38 END
    AND SUBSTR(scope_key, 1, CASE kind
      WHEN 'organization' THEN 4 WHEN 'project' THEN 8
      WHEN 'registry' THEN 9 WHEN 'binary_cache' THEN 6 END) = CASE kind
      WHEN 'organization' THEN 'org:' WHEN 'project' THEN 'project:'
      WHEN 'registry' THEN 'registry:' WHEN 'binary_cache' THEN 'cache:' END
    AND LENGTH(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
      REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
        SUBSTR(scope_key, CASE kind
          WHEN 'organization' THEN 5 WHEN 'project' THEN 9
          WHEN 'registry' THEN 10 WHEN 'binary_cache' THEN 7 END),
        '0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''),
        '6', ''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''),
        'c', ''), 'd', ''), 'e', ''), 'f', '')) = 0))
);

CREATE TABLE user_identities(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- IDTEXT: security-identity columns, binary-collated on mysql so the
  -- composite PK and `identity_user` lookup match OIDC iss/sub byte-for-
  -- byte. Without it, mysql's default case-insensitive collation would
-- collapse case-variant `sub` values onto one user_id and let an
  -- attacker log in as the victim(sec M-6). sqlite/postgres are already
  -- case-sensitive. Email is intentionally left case-insensitive(M-7).
  issuer IDTEXT NOT NULL, -- OIDC iss
  subject IDTEXT NOT NULL, -- OIDC sub
  email TEXT,
  last_login INTEGER,
  PRIMARY KEY(issuer, subject)
);

CREATE TABLE service_accounts(
  id INTEGER PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(org_id, name)
);

CREATE TABLE sessions(
  id_hash TEXT PRIMARY KEY, -- SHA-256 hex of the cookie secret
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  auth_level INTEGER NOT NULL DEFAULT 0, -- 1 = sudo-capable
  last_authenticated_at INTEGER NOT NULL
);

CREATE TABLE change_request_revisions(
  id INTEGER PRIMARY KEY,
  change_id KEYTEXT64 NOT NULL REFERENCES change_requests(change_id) ON DELETE CASCADE,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  op TEXT NOT NULL, -- create|update|delete
  old_json TEXT, -- full object snapshot before
  new_json TEXT, -- full object snapshot after
  seq INTEGER NOT NULL
);

CREATE INDEX change_request_revisions_change_idx ON change_request_revisions(change_id,
  seq);

CREATE TABLE org_idp_configs(
  org_id INTEGER PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
  issuer TEXT NOT NULL,
  authorization_endpoint TEXT NOT NULL,
  token_endpoint TEXT NOT NULL,
  jwks_uri TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_secret_enc LONGTEXT, -- sealed; never plaintext(unbounded; never truncate)
  scopes TEXT NOT NULL DEFAULT 'openid email profile',
  groups_claim TEXT,
  role_map_json LONGTEXT NOT NULL DEFAULT('{}'), -- OIDC group->role JSON(unbounded; never truncate)
  allow_jit INTEGER NOT NULL DEFAULT 1,
  enforce_sso INTEGER NOT NULL DEFAULT 0,
  default_role TEXT NOT NULL DEFAULT 'viewer',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
,
  resource_version INTEGER NOT NULL DEFAULT 1,
  mutation_plan_id KEYTEXT64,
  incarnation_id KEYTEXT64);

CREATE TABLE org_domains(
  domain TEXT PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  txt_challenge TEXT NOT NULL,
  verified_at INTEGER
,
  resource_version INTEGER NOT NULL DEFAULT 1,
  mutation_plan_id KEYTEXT64,
  incarnation_id KEYTEXT64);

CREATE INDEX org_domains_org_idx ON org_domains(org_id);

CREATE TABLE oidc_flows(
  state TEXT PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  nonce TEXT NOT NULL,
  code_verifier TEXT NOT NULL,
  redirect_after TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE webhooks(
  id INTEGER PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret_version_ref KEYTEXT128 NOT NULL, -- immutable secret-provider version; never plaintext
  credential_fingerprint KEYTEXT64 NOT NULL, -- required SHA-256 hex of resolved secret
  events TEXT NOT NULL, -- JSON array of subscribed event-type strings([] = all)
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL DEFAULT 0,
  creation_plan_id KEYTEXT64 UNIQUE
);

CREATE INDEX webhooks_org_idx ON webhooks(org_id);

CREATE TABLE org_quotas(
  org_id INTEGER PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
  max_bytes INTEGER, -- NULL = unlimited
  max_objects INTEGER, -- NULL = unlimited
  max_registries INTEGER, -- NULL = unlimited
  max_tokens INTEGER -- NULL = unlimited
);

CREATE TABLE org_usage(
  org_id INTEGER PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
  used_bytes INTEGER NOT NULL DEFAULT 0,
  object_count INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE TABLE webauthn_credentials(
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE, -- base64url of the raw cred id
  public_key LONGTEXT NOT NULL, -- base64 of the COSE public key(RSA keys exceed 255 chars; never truncate)
  sign_count INTEGER NOT NULL DEFAULT 0, -- authenticator signature counter
  transports TEXT, -- advisory: JSON array of transports
  label TEXT, -- advisory: human label
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials(user_id);

CREATE TABLE change_comments(
  id INTEGER PRIMARY KEY,
  change_id KEYTEXT64 NOT NULL REFERENCES change_requests(change_id) ON DELETE CASCADE,
  actor_kind TEXT NOT NULL,
  actor_id INTEGER,
  actor_label TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX change_comments_change_idx ON change_comments(change_id,
  id);

CREATE TABLE change_reviews(
  id INTEGER PRIMARY KEY,
  change_id KEYTEXT64 NOT NULL REFERENCES change_requests(change_id) ON DELETE CASCADE,
  actor_kind TEXT NOT NULL,
  actor_id INTEGER,
  actor_label TEXT NOT NULL,
  verdict TEXT NOT NULL, -- approve | request_changes
  body TEXT, -- optional review note
  created_at INTEGER NOT NULL
);

CREATE INDEX change_reviews_change_idx ON change_reviews(change_id,
  id);

CREATE TABLE network_policies(
  id KEYTEXT64 PRIMARY KEY,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  owner_scope_key KEYTEXT64 NOT NULL,
  name KEYTEXT64 NOT NULL,
  kind KEYTEXT32 NOT NULL,
  identity_spec_json LONGTEXT NOT NULL,
  identity_fingerprint KEYTEXT128 NOT NULL UNIQUE,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(owner_scope_key, name),
  UNIQUE(id, owner_scope_key),
  CHECK(kind IN('public', 'vpn', 'vpc', 'tunnel', 'source_allowlist', 'trusted_ingress')),
  CHECK(kind <> 'public' OR(id = 'instance:public' AND owner_scope_key = 'instance' AND org_id IS NULL))
);

CREATE TABLE image_snapshot_leases(
  lease_id KEYTEXT64 PRIMARY KEY,
  digest KEYTEXT64 NOT NULL REFERENCES image_snapshots(digest) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);

CREATE TABLE domains(
  id INTEGER PRIMARY KEY,
  stable_id KEYTEXT64 NOT NULL UNIQUE,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  owner_scope_key KEYTEXT64 NOT NULL,
  hostname KEYTEXT255 NOT NULL UNIQUE,
  creation_plan_id KEYTEXT64 NOT NULL UNIQUE,
  last_mutation_plan_id KEYTEXT64,
  dns_configuration_json LONGTEXT,
  dns_state KEYTEXT32 NOT NULL DEFAULT 'unconfigured',
  certificate_configuration_json LONGTEXT,
  certificate_state KEYTEXT32 NOT NULL DEFAULT 'unconfigured',
  verified_at INTEGER,
  observed_at INTEGER,
  observation_error LONGTEXT,
  observation_digest KEYTEXT128,
  probe_location KEYTEXT128,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(id, owner_scope_key),
  CHECK(dns_state IN('unconfigured', 'pending', 'verified', 'failed')),
  CHECK(certificate_state IN('unconfigured', 'pending', 'active', 'failed')),
  CHECK((dns_configuration_json IS NULL AND dns_state = 'unconfigured')
OR(dns_configuration_json IS NOT NULL AND dns_state <> 'unconfigured')),
  CHECK((certificate_configuration_json IS NULL AND certificate_state = 'unconfigured')
OR(certificate_configuration_json IS NOT NULL AND certificate_state <> 'unconfigured')),
  CHECK((verified_at IS NULL AND NOT(dns_state = 'verified' AND certificate_state = 'active'))
OR(verified_at IS NOT NULL AND dns_state = 'verified' AND certificate_state = 'active'))
);

CREATE INDEX domains_owner_idx ON domains(owner_scope_key,
  hostname);

CREATE TABLE gateways(
  id KEYTEXT64 PRIMARY KEY,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  owner_scope_key KEYTEXT64 NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  desired_generation INTEGER,
  observed_generation INTEGER,
  reconciliation_state KEYTEXT16 NOT NULL DEFAULT 'pending',
  reconciliation_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(id, owner_scope_key),
  UNIQUE(id, desired_generation, resource_version),
  CHECK(enabled IN(0, 1)),
  CHECK(reconciliation_state IN('pending', 'reconciling', 'ready', 'failed')),
  CHECK(observed_generation IS NULL OR desired_generation IS NOT NULL)
);

CREATE TABLE authorization_scope_ancestors(
  descendant_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  ancestor_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  depth INTEGER NOT NULL,
  PRIMARY KEY(descendant_scope_key, ancestor_scope_key),
  UNIQUE(descendant_scope_key, depth),
  CHECK(depth >= 0),
  CHECK((depth = 0 AND descendant_scope_key = ancestor_scope_key)
     OR (depth > 0 AND descendant_scope_key <> ancestor_scope_key))
);

CREATE TABLE projects(
  id INTEGER PRIMARY KEY,
  stable_id KEYTEXT64 NOT NULL UNIQUE,
  scope_key KEYTEXT64 NOT NULL UNIQUE,
  owner_scope_key KEYTEXT64 NOT NULL,
  scope_kind KEYTEXT16 NOT NULL DEFAULT 'project',
  org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  path TEXT NOT NULL, -- materialized path; '' = org root
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL DEFAULT 0,
  creation_plan_id KEYTEXT64 UNIQUE,
  UNIQUE(org_id, path),
  FOREIGN KEY(scope_key, scope_kind, stable_id, owner_scope_key)
    REFERENCES authorization_scopes(scope_key, kind, resource_stable_id, parent_scope_key)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CHECK(scope_kind = 'project'),
  CHECK(scope_key = stable_id)
);

CREATE TABLE registries(
  id INTEGER PRIMARY KEY,
  stable_id KEYTEXT64 NOT NULL UNIQUE,
  slug TEXT NOT NULL UNIQUE,
  trust_keys LONGTEXT NOT NULL DEFAULT('[]'), -- JSON array of name:Ed25519:b64(unbounded; never truncate)
  require_signatures INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  project_path TEXT NOT NULL DEFAULT '',
  visibility TEXT NOT NULL DEFAULT 'public',
  crawl_policy TEXT NOT NULL DEFAULT 'allow_all',
  llms_txt_body TEXT,
  scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  owner_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  scope_kind KEYTEXT16 NOT NULL DEFAULT 'registry',
  creation_plan_id KEYTEXT64,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(scope_key, scope_kind, stable_id, owner_scope_key)
    REFERENCES authorization_scopes(scope_key, kind, resource_stable_id, parent_scope_key)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  UNIQUE(id, owner_scope_key),
  UNIQUE(id, scope_key),
  CHECK(scope_kind = 'registry'),
  CHECK(scope_key = stable_id),
  CHECK((org_id IS NULL AND owner_scope_key = 'instance')
     OR (org_id IS NOT NULL AND owner_scope_key <> 'instance'))
);

CREATE UNIQUE INDEX registries_scope_idx ON registries(id,
  scope_key);

CREATE UNIQUE INDEX registries_creation_plan_idx ON registries(
  creation_plan_id
);

CREATE TABLE memberships(
  id INTEGER PRIMARY KEY,
  principal_kind TEXT NOT NULL, -- 'user' | 'service_account'
  principal_id INTEGER NOT NULL,
  scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  role TEXT NOT NULL, -- one of the five role names
  created_at INTEGER NOT NULL,
  UNIQUE(principal_kind, principal_id, scope_key),
  CHECK(principal_kind IN('user', 'service_account')),
  CHECK(role IN('owner', 'admin', 'maintainer', 'developer', 'viewer'))
);

CREATE TABLE invitations(
  id INTEGER PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  role TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE, -- SHA-256 of the invite secret
  created_at INTEGER NOT NULL,
  accepted_at INTEGER,
  expires_at INTEGER NOT NULL,
  cancelled_at INTEGER,
  secret_enc LONGTEXT,
  CHECK(role IN('owner', 'admin', 'maintainer', 'developer', 'viewer'))
);

CREATE TABLE tokens(
  id TEXT PRIMARY KEY,
  hash TEXT UNIQUE NOT NULL, -- SHA-256 hex of the secret
  owner_kind TEXT NOT NULL, -- 'user' | 'service_account'
  owner_id INTEGER NOT NULL,
  scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  permissions TEXT NOT NULL, -- JSON array of permission verbs
  comment TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER,
  last_used_at INTEGER,
  rotated_at INTEGER,
  CHECK(owner_kind IN('user', 'service_account'))
);

CREATE TABLE device_codes(
  device_code_hash TEXT PRIMARY KEY, -- SHA-256 hex of the device-code secret
  user_code TEXT UNIQUE NOT NULL, -- short human-typed code
  scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  permissions TEXT NOT NULL, -- requested permission verbs(JSON array)
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_by_user INTEGER, -- approving user id once approved
  denied INTEGER NOT NULL DEFAULT 0,
  issued_token_id TEXT, -- id of the minted token, once approved
  delivered_at INTEGER -- set by the single successful token poll
,
  last_polled_at INTEGER);

CREATE TABLE signing_keys(
  stable_id KEYTEXT64 PRIMARY KEY,
  scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  name TEXT NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(scope_key, name)
);

CREATE TABLE webhook_deliveries(
  id INTEGER PRIMARY KEY,
  delivery_id KEYTEXT64 NOT NULL UNIQUE,
  outbox_event_id KEYTEXT64 NOT NULL,
  webhook_id INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event TEXT NOT NULL, -- the event-type string
  payload LONGTEXT NOT NULL, -- the JSON body, as signed and POSTed(unbounded; never truncate)
  status TEXT NOT NULL, -- pending|delivered|failed
  response_code INTEGER, -- last HTTP status observed, when any
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  delivered_at INTEGER, -- set when status becomes delivered
  next_attempt_at INTEGER, -- earliest retry time for a pending row
  claim_token KEYTEXT64,
  claim_expires_at INTEGER,
  CHECK(status IN('pending', 'delivered', 'failed')),
  CHECK(attempts >= 0),
  CHECK(length(event) BETWEEN 1 AND 128),
  CHECK(length(payload) <= 1048576),
  CHECK((status = 'pending') = (next_attempt_at IS NOT NULL)),
  CHECK((status = 'delivered') = (delivered_at IS NOT NULL)),
  CHECK((claim_token IS NULL) = (claim_expires_at IS NULL)),
  UNIQUE(webhook_id, outbox_event_id)
);

CREATE TABLE bindings(
  id INTEGER PRIMARY KEY,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind KEYTEXT16 NOT NULL,
  is_instance_default INTEGER NOT NULL DEFAULT 0,
  instance_default_key KEYTEXT16,
  created_at INTEGER NOT NULL,
  stable_id KEYTEXT64 NOT NULL,
  owner_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  local_root_path LONGTEXT,
  object_bucket KEYTEXT255,
  object_prefix KEYTEXT512,
  endpoint_scheme KEYTEXT16,
  endpoint_host_kind KEYTEXT16,
  endpoint_host_bytes BLOB,
  endpoint_port INTEGER,
  signing_region KEYTEXT64,
  access_mode KEYTEXT16,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(org_id, name),
  UNIQUE(instance_default_key),
  FOREIGN KEY(owner_scope_key, org_id)
    REFERENCES authorization_scopes(scope_key, org_id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CHECK(is_instance_default IN(0, 1)),
  CHECK((is_instance_default = 1 AND instance_default_key = 'singleton')
     OR (is_instance_default = 0 AND instance_default_key IS NULL)),
  CHECK((is_instance_default = 1 AND org_id IS NULL
         AND owner_scope_key = 'instance')
     OR (is_instance_default = 0 AND org_id IS NOT NULL
         AND owner_scope_key <> 'instance')),
  CHECK((is_instance_default = 1 AND kind = 'local_fs'
         AND local_root_path IS NOT NULL
         AND length(local_root_path) > 0
         AND substr(local_root_path, 1, 1) = '/'
         AND object_bucket IS NULL
         AND object_prefix IS NULL
         AND endpoint_scheme IS NULL
         AND endpoint_host_kind IS NULL
         AND endpoint_host_bytes IS NULL
         AND endpoint_port IS NULL
         AND signing_region IS NULL
         AND access_mode IS NULL)
     OR (is_instance_default = 1 AND kind = 'deployment_r2'
         AND local_root_path IS NULL
         AND object_bucket IS NOT NULL AND length(object_bucket) > 0
         AND object_prefix = ''
         AND endpoint_scheme IS NULL AND endpoint_host_kind IS NULL
         AND endpoint_host_bytes IS NULL AND endpoint_port IS NULL
         AND signing_region IS NULL AND access_mode IS NULL)
     OR (is_instance_default = 0 AND kind IN('s3', 'r2')
         AND local_root_path IS NULL
         AND object_bucket IS NOT NULL
         AND length(object_bucket) > 0
         AND object_prefix IS NOT NULL
         AND endpoint_scheme = 'https'
         AND endpoint_host_kind IN('dns', 'ipv4', 'ipv6')
         AND endpoint_host_bytes IS NOT NULL
         AND ((endpoint_host_kind = 'dns' AND length(endpoint_host_bytes) > 0)
           OR (endpoint_host_kind = 'ipv4' AND length(endpoint_host_bytes) = 4)
           OR (endpoint_host_kind = 'ipv6' AND length(endpoint_host_bytes) = 16))
         AND endpoint_port BETWEEN 1 AND 65535
         AND signing_region IS NOT NULL
         AND length(signing_region) > 0
         AND access_mode IN('public', 'private')))
);

CREATE UNIQUE INDEX bindings_stable_idx ON bindings(stable_id);

CREATE TABLE binary_caches(
  id INTEGER PRIMARY KEY,
  stable_id KEYTEXT64 NOT NULL UNIQUE,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  visibility TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 40,
  compression TEXT NOT NULL DEFAULT 'zstd',
  want_mass_query INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  deleted_at INTEGER,
  purge_after INTEGER,
  scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  owner_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  scope_kind KEYTEXT16 NOT NULL DEFAULT 'binary_cache',
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(scope_key, scope_kind, stable_id, owner_scope_key)
    REFERENCES authorization_scopes(scope_key, kind, resource_stable_id, parent_scope_key)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  UNIQUE(id, owner_scope_key),
  UNIQUE(id, scope_key),
  CHECK(scope_kind = 'binary_cache'),
  CHECK(scope_key = stable_id),
  CHECK((org_id IS NULL AND owner_scope_key = 'instance')
     OR (org_id IS NOT NULL AND owner_scope_key <> 'instance'))
);

CREATE UNIQUE INDEX binary_caches_id_slug_idx ON binary_caches(id,
  slug);

CREATE UNIQUE INDEX binary_caches_id_stable_id_idx ON binary_caches(id,
  stable_id);

CREATE UNIQUE INDEX binary_caches_scope_idx ON binary_caches(id,
  scope_key);

CREATE TABLE network_policy_revisions(
  boundary_id KEYTEXT64 NOT NULL REFERENCES network_policies(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL,
  protected_transport_required INTEGER NOT NULL,
  trusted_ingress_kind KEYTEXT32 NOT NULL,
  trusted_ingress_configuration LONGTEXT NOT NULL,
  source_allowlist_cidrs LONGTEXT,
  probe_location_configuration LONGTEXT NOT NULL,
  content_digest KEYTEXT128 NOT NULL,
  created_by KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(boundary_id, revision),
  UNIQUE(boundary_id, revision, protected_transport_required, trusted_ingress_kind),
  CHECK(revision > 0),
  CHECK(protected_transport_required IN(0, 1)),
  CHECK(trusted_ingress_kind IN('none', 'mtls', 'signed_assertion'))
);

CREATE TABLE network_policy_consumer_scopes(
  boundary_id KEYTEXT64 NOT NULL REFERENCES network_policies(id) ON DELETE CASCADE,
  consumer_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  grant_generation INTEGER NOT NULL,
  grant_kind KEYTEXT32 NOT NULL,
  state KEYTEXT16 NOT NULL,
  granted_by KEYTEXT128 NOT NULL,
  granted_at INTEGER NOT NULL,
  revoked_by KEYTEXT128,
  revoked_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(boundary_id, consumer_scope_key),
  UNIQUE(boundary_id, consumer_scope_key, grant_generation, state),
  CHECK(grant_generation > 0),
  CHECK(grant_kind IN('owner', 'instance_default', 'explicit')),
  CHECK((state = 'active' AND revoked_by IS NULL AND revoked_at IS NULL)
OR(state = 'revoked' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL))
);

CREATE TABLE topology_event_outbox(
  event_id KEYTEXT64 PRIMARY KEY,
  event_name KEYTEXT128 NOT NULL,
  owner_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE CASCADE ON UPDATE RESTRICT,
  resource_kind KEYTEXT32 NOT NULL,
  resource_stable_id KEYTEXT255 NOT NULL,
  resource_generation_key INTEGER NOT NULL DEFAULT 0,
  actor_kind KEYTEXT32 NOT NULL,
  actor_id INTEGER,
  actor_label TEXT NOT NULL,
  payload_json LONGTEXT NOT NULL,
  occurred_at INTEGER NOT NULL,
  materialized_at INTEGER,
  CHECK(resource_generation_key >= 0),
  CHECK(length(payload_json) <= 1048576),
  CHECK(actor_kind IN('user', 'service_account', 'key', 'system')),
  CHECK(resource_kind IN('organization', 'project', 'binding',
    'registry', 'binary_cache', 'placement', 'domain',
    'network_policy', 'endpoint', 'gateway', 'route',
    'placement_policy', 'retention_subscription', 'population_target',
    'cache_gc_generation', 'binding_credential', 'webhook'))
);

CREATE TABLE topology_operations(
  operation_id KEYTEXT64 PRIMARY KEY,
  operation_kind KEYTEXT64 NOT NULL,
  authorization_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE CASCADE ON UPDATE RESTRICT,
  control_permission KEYTEXT32 NOT NULL,
  primary_target_kind KEYTEXT32 NOT NULL,
  primary_target_stable_id KEYTEXT255 NOT NULL,
  primary_target_generation_key INTEGER NOT NULL DEFAULT 0,
  primary_target_configuration_digest KEYTEXT128 NOT NULL DEFAULT '',
  state KEYTEXT32 NOT NULL,
  progress_current INTEGER NOT NULL DEFAULT 0,
  progress_total INTEGER,
  detail_json LONGTEXT NOT NULL DEFAULT('{}'),
  error LONGTEXT,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK(state IN('pending', 'running', 'succeeded', 'failed', 'cancelled')),
  CHECK(control_permission IN('read', 'publish', 'channel.advance', 'keys.manage',
    'tokens.self', 'tokens.manage', 'members.manage', 'registry.configure',
    'storage.manage', 'binding.read', 'binding.manage',
    'binding.grant', 'placement.read', 'placement.manage',
    'placement_policy.read', 'placement_policy.manage', 'domain.read',
    'domain.manage', 'network_policy.read', 'network_policy.manage',
    'network_policy.grant', 'endpoint.read',
    'endpoint.manage', 'endpoint.grant',
    'gateway.read', 'gateway.manage', 'gateway.grant',
    'route.read', 'route.manage', 'topology.reconcile', 'cache.retention.manage',
    'cache.gc.plan', 'cache.gc.execute', 'cache.lease.self',
    'audit.read', 'iam.admin')),
  CHECK(primary_target_kind IN('registry', 'binary_cache', 'placement', 'domain',
    'network_policy', 'endpoint', 'gateway', 'route',
    'placement_policy', 'retention_subscription', 'population_target',
    'cache_gc_generation', 'binding')),
  CHECK(primary_target_generation_key >= 0),
  CHECK(progress_current >= 0),
  CHECK(progress_total IS NULL OR progress_total >= progress_current),
  CHECK((state = 'pending' AND started_at IS NULL AND finished_at IS NULL)
OR(state = 'running' AND started_at IS NOT NULL AND finished_at IS NULL)
OR(state IN('succeeded', 'failed', 'cancelled')
AND started_at IS NOT NULL AND finished_at IS NOT NULL)),
  CHECK(started_at IS NULL OR started_at >= created_at),
  CHECK(finished_at IS NULL OR finished_at >= started_at),
  CHECK(state <> 'succeeded' OR error IS NULL),
  CHECK(state <> 'failed' OR error IS NOT NULL),
  UNIQUE(operation_id, primary_target_kind, primary_target_stable_id)
);

CREATE TABLE registry_index(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  state TEXT NOT NULL, -- fresh|indexing|stale|failed
  error TEXT,
  last_indexed_commit TEXT,
  name TEXT,
  description TEXT,
  indexed_at INTEGER,
  refs_digest TEXT,
  cache_stack LONGTEXT,
  readme TEXT,
  generation INTEGER NOT NULL DEFAULT 0,
  content_digest KEYTEXT128,
  documentation_projection_generation INTEGER NOT NULL DEFAULT 0,
  support_json TEXT,
  CHECK(generation >= 0),
  CHECK((generation = 0 AND content_digest IS NULL)
    OR (generation > 0 AND content_digest IS NOT NULL))
);

CREATE TABLE packages(
  id INTEGER PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  homepage TEXT,
  license TEXT NOT NULL,
  maintainer TEXT NOT NULL,
  sysroot INTEGER NOT NULL,
  UNIQUE(registry_id, name)
);

CREATE TABLE channels(
  id INTEGER PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  frontier TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, name)
);

CREATE TABLE releases(
  id INTEGER PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  semver KEYTEXT255 NOT NULL,
  tag_oid TEXT NOT NULL,
  commit_oid TEXT NOT NULL,
  signer TEXT,
  tagged_at INTEGER,
  pack_present INTEGER NOT NULL DEFAULT 0,
  UNIQUE(registry_id, semver),
  UNIQUE(id, registry_id)
);

CREATE UNIQUE INDEX releases_id_registry_idx ON releases(id,
  registry_id);

CREATE TABLE key_rosters(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,
  public_key LONGTEXT NOT NULL, -- name:Alg:<base64> key line(unbounded; never truncate)
  status TEXT NOT NULL, -- active|revoked
  PRIMARY KEY(registry_id, key_id)
);

CREATE TABLE channel_floors(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  channel TEXT NOT NULL,
  floor TEXT NOT NULL,
  PRIMARY KEY(registry_id, channel)
);

CREATE TABLE signing_key_generations(
  signing_key_id KEYTEXT64 NOT NULL REFERENCES signing_keys(stable_id) ON DELETE RESTRICT,
  generation INTEGER NOT NULL,
  algorithm TEXT NOT NULL,
  public_key LONGTEXT NOT NULL,
  public_key_fingerprint KEYTEXT64 NOT NULL,
  custody TEXT NOT NULL,
  state TEXT NOT NULL,
  active_slot INTEGER,
  created_at INTEGER NOT NULL,
  retired_at INTEGER,
  PRIMARY KEY(signing_key_id, generation),
  CHECK(generation > 0),
  CHECK(algorithm = 'ed25519'),
  CHECK(custody = 'external'),
  CHECK(state IN('active', 'retired')),
  CHECK((state = 'active' AND active_slot = 1)
    OR (state = 'retired' AND active_slot IS NULL)),
  CHECK((state = 'active' AND retired_at IS NULL)
    OR (state = 'retired' AND retired_at IS NOT NULL)),
  UNIQUE(signing_key_id, active_slot)
);

CREATE TABLE mirror_sources(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  upstream_url TEXT NOT NULL,
  mode TEXT NOT NULL, -- full | pullthrough
  verify INTEGER NOT NULL DEFAULT 1,
  schedule_secs INTEGER NOT NULL DEFAULT 3600,
  last_sync_at INTEGER,
  last_sync_status TEXT, -- ok | failed
  last_sync_error TEXT,
  upstream_frontier TEXT,
  refspec TEXT NOT NULL DEFAULT '',
  auth_secret_ref TEXT NOT NULL DEFAULT '',
  resource_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE publish_leases(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  holder_token_id TEXT NOT NULL,
  deadline INTEGER NOT NULL
);

CREATE TABLE binding_credential_revisions(
  binding_id INTEGER NOT NULL REFERENCES bindings(id) ON DELETE CASCADE,
  purpose KEYTEXT16 NOT NULL,
  generation INTEGER NOT NULL,
  secret_version_ref KEYTEXT128 NOT NULL,
  validation_state KEYTEXT16 NOT NULL DEFAULT 'unknown',
  validated_at INTEGER,
  validation_error LONGTEXT,
  credential_fingerprint KEYTEXT64 NOT NULL, -- required SHA-256 hex of resolved secret
  created_by KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(binding_id, purpose, generation),
  UNIQUE(binding_id, purpose, secret_version_ref),
  CHECK(purpose IN('read', 'write', 'delete', 'list', 'presign')),
  CHECK(generation > 0),
  CHECK(validation_state IN('unknown', 'validating', 'valid', 'invalid', 'retired')),
  CHECK((validation_state IN('unknown', 'validating') AND validated_at IS NULL)
OR(validation_state IN('valid', 'invalid', 'retired') AND validated_at IS NOT NULL)),
  CHECK(validation_state = 'invalid' OR validation_error IS NULL)
);

CREATE TABLE binding_consumer_scopes(
  binding_id INTEGER NOT NULL REFERENCES bindings(id) ON DELETE CASCADE,
  consumer_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  grant_generation INTEGER NOT NULL,
  grant_kind KEYTEXT32 NOT NULL,
  state KEYTEXT16 NOT NULL,
  granted_by KEYTEXT128 NOT NULL,
  granted_at INTEGER NOT NULL,
  revoked_by KEYTEXT128,
  revoked_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(binding_id, consumer_scope_key),
  UNIQUE(binding_id, consumer_scope_key, grant_generation, state),
  CHECK(grant_generation > 0),
  CHECK(grant_kind IN('owner', 'instance_default', 'explicit')),
  CHECK((state = 'active' AND revoked_by IS NULL AND revoked_at IS NULL)
OR(state = 'revoked' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL))
);

CREATE TABLE registry_publications(
  publication_id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id),
  ordinal INTEGER NOT NULL,
  generation KEYTEXT128 NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  refs_digest KEYTEXT128 NOT NULL,
  default_commit KEYTEXT128,
  parent_publication_id KEYTEXT64,
  state KEYTEXT32 NOT NULL,
  mutation_version INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  retired_at INTEGER,
  CHECK(ordinal > 0),
  CHECK(state IN('preparing', 'writing_pointers', 'ready', 'failed', 'retired')),
  CHECK((state IN('preparing', 'writing_pointers')
AND completed_at IS NULL AND retired_at IS NULL)
OR(state = 'ready' AND completed_at IS NOT NULL AND retired_at IS NULL)
OR(state = 'failed' AND completed_at IS NOT NULL AND retired_at IS NULL)
OR(state = 'retired' AND completed_at IS NOT NULL
AND retired_at IS NOT NULL AND retired_at >= completed_at)),
  UNIQUE(registry_id, ordinal),
  UNIQUE(registry_id, generation),
  UNIQUE(registry_id, manifest_digest),
  UNIQUE(publication_id, registry_id),
  FOREIGN KEY(parent_publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id)
);

CREATE TABLE network_policy_observations(
  boundary_id KEYTEXT64 NOT NULL,
  revision INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  protected_transport_observed INTEGER NOT NULL DEFAULT 0,
  trusted_ingress_observed KEYTEXT32 NOT NULL DEFAULT 'none',
  observed_at INTEGER NOT NULL,
  error LONGTEXT,
  PRIMARY KEY(boundary_id, revision),
  FOREIGN KEY(boundary_id, revision)
  REFERENCES network_policy_revisions(boundary_id, revision) ON DELETE CASCADE,
  CHECK(state IN('unknown', 'declared', 'probing', 'verified', 'degraded', 'failed')),
  CHECK(protected_transport_observed IN(0, 1)),
  CHECK(state = 'failed' OR error IS NULL)
);

CREATE TABLE network_policy_revision_lifecycle(
  boundary_id KEYTEXT64 NOT NULL,
  revision INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  activation_mode KEYTEXT16 NOT NULL,
  consumer_version INTEGER NOT NULL DEFAULT 0,
  activated_at INTEGER,
  retired_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(boundary_id, revision),
  UNIQUE(boundary_id, revision, state),
  FOREIGN KEY(boundary_id, revision)
  REFERENCES network_policy_revisions(boundary_id, revision) ON DELETE CASCADE,
  CHECK(state IN('staged', 'activating', 'active', 'retiring', 'retired')),
  CHECK(activation_mode IN('overlap', 'coordinated', 'system')),
  CHECK((state IN('staged', 'activating') AND activated_at IS NULL AND retired_at IS NULL)
OR(state IN('active', 'retiring') AND activated_at IS NOT NULL AND retired_at IS NULL)
OR(state = 'retired' AND activated_at IS NOT NULL AND retired_at IS NOT NULL))
);

CREATE TABLE placement_policies(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER REFERENCES registries(id) ON DELETE CASCADE,
  cache_id INTEGER REFERENCES binary_caches(id) ON DELETE CASCADE,
  name KEYTEXT64 NOT NULL,
  creation_token KEYTEXT64 NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  UNIQUE(registry_id, name),
  UNIQUE(cache_id, name),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id)
);

CREATE TABLE cache_retention_subscriptions(
  id INTEGER PRIMARY KEY,
  cache_id INTEGER NOT NULL REFERENCES binary_caches(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  selector_json LONGTEXT NOT NULL,
  selector_digest KEYTEXT128 NOT NULL,
  removal_grace_secs INTEGER NOT NULL DEFAULT 0,
  exposure_acknowledged_at INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_successful_revision KEYTEXT128,
  last_refresh_at INTEGER,
  refresh_state KEYTEXT32 NOT NULL DEFAULT 'stale',
  refresh_error LONGTEXT,
  retired_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK(refresh_state IN('fresh', 'stale', 'refreshing', 'failed')),
  CHECK(removal_grace_secs >= 0),
  CHECK(enabled IN(0, 1)),
  CHECK(retired_at IS NULL OR enabled = 0),
  UNIQUE(cache_id, registry_id),
  UNIQUE(id, cache_id, registry_id)
);

CREATE TABLE manual_retention_roots(
  id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL REFERENCES binary_caches(id) ON DELETE CASCADE,
  store_hash KEYTEXT64 NOT NULL,
  protection_kind KEYTEXT16 NOT NULL,
  reason LONGTEXT NOT NULL,
  owner_kind KEYTEXT32 NOT NULL,
  owner_id INTEGER NOT NULL,
  created_by KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  deleted_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(id, cache_id),
  UNIQUE(id, cache_id, store_hash),
  CHECK(protection_kind IN('indefinite', 'leased')),
  CHECK(owner_kind IN('user', 'service_account') AND owner_id > 0),
  CHECK(resource_version > 0)
);

CREATE TABLE operation_secondary_targets(
  operation_id KEYTEXT64 NOT NULL REFERENCES topology_operations(operation_id) ON DELETE CASCADE,
  role KEYTEXT32 NOT NULL,
  target_kind KEYTEXT32 NOT NULL,
  stable_id KEYTEXT255 NOT NULL,
  authorization_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE CASCADE ON UPDATE RESTRICT,
  control_permission KEYTEXT32 NOT NULL,
  generation_key INTEGER NOT NULL DEFAULT 0,
  configuration_digest KEYTEXT128 NOT NULL DEFAULT '',
  PRIMARY KEY(operation_id, role, target_kind, stable_id, generation_key),
  UNIQUE(operation_id, target_kind, stable_id),
  UNIQUE(operation_id, role, target_kind, stable_id),
  CHECK(role IN('source', 'destination', 'placement', 'policy', 'subscription', 'generation')),
  CHECK(target_kind IN('registry', 'binary_cache', 'placement', 'domain',
    'network_policy', 'endpoint', 'gateway', 'route',
    'placement_policy', 'retention_subscription', 'population_target',
    'cache_gc_generation', 'binding')),
  CHECK(generation_key >= 0),
  CHECK(control_permission IN('read', 'publish', 'channel.advance', 'keys.manage',
    'tokens.self', 'tokens.manage', 'members.manage', 'registry.configure',
    'storage.manage', 'binding.read', 'binding.manage',
    'binding.grant', 'placement.read', 'placement.manage',
    'placement_policy.read', 'placement_policy.manage', 'domain.read',
    'domain.manage', 'network_policy.read', 'network_policy.manage',
    'network_policy.grant', 'endpoint.read',
    'endpoint.manage', 'endpoint.grant',
    'gateway.read', 'gateway.manage', 'gateway.grant',
    'route.read', 'route.manage', 'topology.reconcile', 'cache.retention.manage',
    'cache.gc.plan', 'cache.gc.execute', 'cache.lease.self',
    'audit.read', 'iam.admin'))
);

CREATE TABLE topology_pin_resolution_jobs(
  operation_id KEYTEXT64 NOT NULL REFERENCES topology_operations(operation_id) ON DELETE CASCADE,
  pin_id KEYTEXT64 NOT NULL,
  action_kind KEYTEXT32 NOT NULL,
  source_boundary_id KEYTEXT64 NOT NULL,
  source_boundary_revision INTEGER NOT NULL,
  source_consumer_scope_key KEYTEXT64 NOT NULL,
  source_grant_generation INTEGER NOT NULL,
  source_usage_kind KEYTEXT32 NOT NULL,
  source_target_kind KEYTEXT32 NOT NULL,
  source_target_stable_id KEYTEXT64 NOT NULL,
  source_target_generation_key INTEGER NOT NULL,
  source_target_configuration_digest KEYTEXT128 NOT NULL,
  source_target_resource_version INTEGER NOT NULL,
  replacement_target_kind KEYTEXT32,
  replacement_target_stable_id KEYTEXT64,
  replacement_target_generation_key INTEGER,
  replacement_target_configuration_digest KEYTEXT128,
  replacement_target_resource_version INTEGER,
  state KEYTEXT16 NOT NULL DEFAULT 'pending',
  attempt INTEGER NOT NULL DEFAULT 0,
  error LONGTEXT,
  started_at INTEGER,
  finished_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(operation_id, pin_id),
  UNIQUE(pin_id),
  CHECK(action_kind IN('move_endpoint', 'replace_route', 'release')),
  CHECK(source_target_kind IN('endpoint', 'route')),
  CHECK(source_boundary_revision > 0 AND source_grant_generation > 0),
  CHECK(source_target_generation_key > 0 AND source_target_resource_version > 0),
  CHECK((action_kind = 'release' AND replacement_target_kind IS NULL
    AND replacement_target_stable_id IS NULL
    AND replacement_target_generation_key IS NULL
    AND replacement_target_configuration_digest IS NULL
    AND replacement_target_resource_version IS NULL)
  OR(action_kind <> 'release' AND replacement_target_kind IS NOT NULL
    AND replacement_target_stable_id IS NOT NULL
    AND replacement_target_generation_key IS NOT NULL
    AND replacement_target_configuration_digest IS NOT NULL
    AND replacement_target_resource_version IS NOT NULL)),
  CHECK(state IN('pending', 'running', 'succeeded', 'failed')),
  CHECK(attempt >= 0 AND resource_version > 0),
  CHECK((state = 'pending' AND started_at IS NULL AND finished_at IS NULL AND error IS NULL)
    OR(state = 'running' AND started_at IS NOT NULL AND finished_at IS NULL AND error IS NULL)
    OR(state = 'succeeded' AND started_at IS NOT NULL AND finished_at IS NOT NULL AND error IS NULL)
    OR(state = 'failed' AND started_at IS NOT NULL AND finished_at IS NOT NULL AND error IS NOT NULL))
);

CREATE TABLE topology_operation_mutations(
  operation_id KEYTEXT64 NOT NULL REFERENCES topology_operations(operation_id) ON DELETE CASCADE,
  idempotency_key KEYTEXT128 NOT NULL,
  mutation_kind KEYTEXT16 NOT NULL,
  expected_resource_version INTEGER NOT NULL,
  resulting_resource_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(operation_id, idempotency_key),
  CHECK(mutation_kind IN('cancel', 'retry')),
  CHECK(expected_resource_version > 0),
  CHECK(resulting_resource_version = expected_resource_version + 1)
);

CREATE TABLE domain_probe_observations(
  operation_id KEYTEXT64 PRIMARY KEY REFERENCES topology_operations(operation_id) ON DELETE CASCADE,
  domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  desired_resource_version INTEGER NOT NULL,
  evidence_json LONGTEXT NOT NULL,
  evidence_digest KEYTEXT128 NOT NULL,
  probe_location KEYTEXT128 NOT NULL,
  observed_at INTEGER NOT NULL,
  UNIQUE(domain_id, evidence_digest)
);

CREATE TABLE endpoints(
  id KEYTEXT64 PRIMARY KEY,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  owner_scope_key KEYTEXT64 NOT NULL,
  scheme KEYTEXT16 NOT NULL,
  domain_id INTEGER,
  ipv4_bytes BLOB,
  ipv6_bytes BLOB,
  effective_port INTEGER NOT NULL,
  network_policy_id KEYTEXT64 NOT NULL,
  cleartext_acknowledged_at INTEGER,
  desired_generation INTEGER,
  endpoint_identity_digest KEYTEXT128 NOT NULL UNIQUE,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(id, owner_scope_key),
  UNIQUE(id, network_policy_id),
  CHECK((CASE WHEN domain_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN ipv4_bytes IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN ipv6_bytes IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK(scheme IN('https', 'http')),
  CHECK(effective_port > 0 AND effective_port <= 65535),
  CHECK(scheme = 'https' OR cleartext_acknowledged_at IS NOT NULL),
  FOREIGN KEY(domain_id, owner_scope_key) REFERENCES domains(id, owner_scope_key),
  FOREIGN KEY(network_policy_id, owner_scope_key)
  REFERENCES network_policy_consumer_scopes(boundary_id, consumer_scope_key)
);

CREATE TABLE cache_inventory_generations(
  cache_id INTEGER NOT NULL REFERENCES binary_caches(id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  owner_token KEYTEXT64 NOT NULL,
  lease_expires_at INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  content_digest KEYTEXT128,
  published_at INTEGER,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(cache_id, generation),
  UNIQUE(generation, cache_id),
  CHECK(generation > 0),
  CHECK(length(owner_token) > 0),
  CHECK(lease_expires_at > created_at),
  CHECK((state = 'building' AND content_digest IS NULL AND published_at IS NULL)
OR(state = 'published' AND content_digest IS NOT NULL AND published_at IS NOT NULL)
OR(state = 'failed' AND published_at IS NULL))
);

CREATE TABLE network_policy_serving_pins(
  pin_id KEYTEXT64 PRIMARY KEY,
  boundary_id KEYTEXT64 NOT NULL,
  revision INTEGER NOT NULL,
  consumer_scope_key KEYTEXT64 NOT NULL,
  grant_generation INTEGER NOT NULL,
  grant_state KEYTEXT16 NOT NULL DEFAULT 'active',
  usage_kind KEYTEXT32 NOT NULL,
  target_kind KEYTEXT32 NOT NULL,
  target_stable_id KEYTEXT64 NOT NULL,
  target_generation_key INTEGER NOT NULL,
  target_configuration_digest KEYTEXT128 NOT NULL,
  acquired_by KEYTEXT128 NOT NULL,
  acquired_at INTEGER NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(boundary_id, revision, usage_kind, target_kind, target_stable_id,
target_generation_key, target_configuration_digest),
  FOREIGN KEY(boundary_id, revision)
  REFERENCES network_policy_revisions(boundary_id, revision),
  FOREIGN KEY(boundary_id, consumer_scope_key, grant_generation, grant_state)
  REFERENCES network_policy_consumer_scopes(boundary_id, consumer_scope_key, grant_generation, state),
  CHECK(grant_state = 'active')
);

CREATE TABLE cache_gc_policies(
  cache_id INTEGER PRIMARY KEY REFERENCES binary_caches(id) ON DELETE CASCADE,
  unreferenced_grace_secs INTEGER NOT NULL,
  soft_max_bytes INTEGER,
  soft_max_objects INTEGER,
  schedule_secs INTEGER,
  deletion_concurrency INTEGER NOT NULL,
  retry_initial_secs INTEGER NOT NULL,
  retry_max_secs INTEGER NOT NULL,
  retry_max_attempts INTEGER NOT NULL,
  tombstone_retention_secs INTEGER NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK(unreferenced_grace_secs >= 0),
  CHECK(soft_max_bytes IS NULL OR soft_max_bytes >= 0),
  CHECK(soft_max_objects IS NULL OR soft_max_objects >= 0),
  CHECK(schedule_secs IS NULL OR schedule_secs > 0),
  CHECK(deletion_concurrency > 0),
  CHECK(retry_initial_secs > 0),
  CHECK(retry_max_secs >= retry_initial_secs),
  CHECK(retry_max_attempts > 0),
  CHECK(tombstone_retention_secs >= 0),
  CHECK(resource_version > 0)
);

CREATE TABLE cache_gc_deletion_capacity(
  cache_id INTEGER PRIMARY KEY REFERENCES binary_caches(id) ON DELETE CASCADE,
  running_count INTEGER NOT NULL DEFAULT 0,
  CHECK(running_count >= 0)
);

CREATE TABLE cache_object_mutation_fences(
  cache_id INTEGER NOT NULL REFERENCES binary_caches(id) ON DELETE CASCADE,
  store_hash KEYTEXT64 NOT NULL,
  operation_id KEYTEXT64 NOT NULL,
  operation_target_kind KEYTEXT32 NOT NULL DEFAULT('binary_cache'),
  operation_target_stable_id KEYTEXT255 NOT NULL,
  kind KEYTEXT32 NOT NULL,
  state KEYTEXT16 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(cache_id, store_hash, operation_id),
  CHECK(kind IN('upload', 'population', 'replication', 'repair')),
  CHECK(operation_target_kind = 'binary_cache'),
  CHECK(state IN('active', 'completed', 'cancelled')),
  CHECK(resource_version > 0),
  FOREIGN KEY(operation_id) REFERENCES topology_operations(operation_id),
  FOREIGN KEY(operation_id, operation_target_kind, operation_target_stable_id)
  REFERENCES topology_operations(operation_id, primary_target_kind, primary_target_stable_id),
  FOREIGN KEY(cache_id, operation_target_stable_id)
  REFERENCES binary_caches(id, stable_id)
);

CREATE TABLE cache_gc_generations(
  generation_id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL REFERENCES binary_caches(id) ON DELETE CASCADE,
  state KEYTEXT16 NOT NULL,
  cutoff_at INTEGER NOT NULL,
  expected_epoch INTEGER NOT NULL,
  root_generation INTEGER NOT NULL,
  object_graph_generation INTEGER NOT NULL,
  inventory_generation INTEGER NOT NULL,
  gc_policy_version INTEGER NOT NULL,
  topology_version INTEGER NOT NULL,
  parent_mark_generation_id KEYTEXT64,
  scanned_object_count INTEGER NOT NULL DEFAULT 0,
  root_count INTEGER NOT NULL,
  marked_object_count INTEGER NOT NULL,
  coverage_error_count INTEGER NOT NULL,
  error LONGTEXT,
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  UNIQUE(generation_id, cache_id),
  CHECK(state IN('building', 'complete', 'failed')),
  CHECK(expected_epoch >= 0 AND root_generation >= 0
AND object_graph_generation >= 0 AND inventory_generation > 0
AND gc_policy_version > 0 AND topology_version >= 0),
  CHECK(scanned_object_count >= 0 AND root_count >= 0 AND marked_object_count >= 0
AND coverage_error_count >= 0),
  CHECK((state = 'building' AND completed_at IS NULL AND error IS NULL)
OR(state = 'complete' AND completed_at IS NOT NULL AND error IS NULL)
OR(state = 'failed' AND completed_at IS NOT NULL AND error IS NOT NULL)),
  FOREIGN KEY(parent_mark_generation_id, cache_id)
  REFERENCES cache_gc_generations(generation_id, cache_id)
);

CREATE TABLE refresh_token_families(
  id TEXT PRIMARY KEY,
  token_id TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE live_invitations(
  org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  invitation_id INTEGER NOT NULL UNIQUE REFERENCES invitations(id) ON DELETE CASCADE,
  PRIMARY KEY(org_id, email, scope_key)
);

CREATE TABLE placement_scan_claims(
  operation_id KEYTEXT64 PRIMARY KEY
    REFERENCES topology_operations(operation_id) ON DELETE CASCADE,
  claim_token KEYTEXT64 NOT NULL UNIQUE,
  operation_resource_version INTEGER NOT NULL,
  heartbeat_at INTEGER NOT NULL,
  lease_expires_at INTEGER NOT NULL,
  CHECK(operation_resource_version > 0),
  CHECK(lease_expires_at > heartbeat_at)
);

CREATE TABLE registry_index_build_heads(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  build_id KEYTEXT64 NOT NULL,
  owner_token KEYTEXT64,
  base_generation INTEGER NOT NULL,
  target_generation INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  lease_expires_at INTEGER,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  content_digest KEYTEXT128,
  error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK(base_generation >= 0),
  CHECK(target_generation = base_generation + 1),
  CHECK(state IN('building', 'published', 'no_change', 'failed')),
  CHECK(resource_version > 0),
  CHECK((state = 'building' AND owner_token IS NOT NULL
         AND lease_expires_at IS NOT NULL AND finished_at IS NULL)
     OR (state <> 'building' AND owner_token IS NULL
         AND lease_expires_at IS NULL AND finished_at IS NOT NULL))
);

CREATE TABLE registry_catalog_artifacts(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  source_revision KEYTEXT128 NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  package_version KEYTEXT64 NOT NULL,
  platform KEYTEXT64 NOT NULL,
  artifact_kind KEYTEXT32 NOT NULL,
  store_path KEYTEXT512 NOT NULL,
  store_hash KEYTEXT64 NOT NULL,
  metadata_digest KEYTEXT128 NOT NULL,
  PRIMARY KEY(registry_id, source_revision, package_name, package_version,
platform, artifact_kind, store_hash),
  CHECK(artifact_kind IN(
    'output', 'image', 'source_derivation', 'expose', 'config',
    'evaluation_base_lib', 'documentation'
  ))
);

CREATE TABLE package_documentation(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  indexed_commit KEYTEXT64 NOT NULL,
  package_name TEXT NOT NULL,
  package_version TEXT NOT NULL,
  platform TEXT NOT NULL,
  format KEYTEXT64 NOT NULL,
  store_path TEXT NOT NULL,
  nar_hash KEYTEXT128 NOT NULL,
  nar_size INTEGER NOT NULL,
  document_sha256 KEYTEXT128 NOT NULL,
  document_size INTEGER NOT NULL,
  semantic_schema_sha256 KEYTEXT128 NOT NULL,
  system_module_nar_hash KEYTEXT128,
  PRIMARY KEY(registry_id, package_name, package_version, platform),
  CHECK(format = 'aos.package-documentation/v1+json'),
  CHECK(nar_size > 0 AND nar_size <= 4194304),
  CHECK(document_size > 0 AND document_size <= 4194304)
);

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

CREATE TABLE oci_repositories(
  id INTEGER PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  name KEYTEXT255 NOT NULL,
  visibility KEYTEXT16 NOT NULL DEFAULT 'inherit',
  lifecycle_state KEYTEXT16 NOT NULL DEFAULT 'active',
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(registry_id, name),
  UNIQUE(id, registry_id),
  -- Container repositories inherit their owning AOS registry's visibility;
  -- repository-local overrides would otherwise bypass registry-scoped auth.
  CHECK(visibility = 'inherit'),
  CHECK(lifecycle_state IN('active', 'deleting', 'deleted'))
);

CREATE TABLE oci_retention_policies(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  untagged_grace_seconds INTEGER NOT NULL,
  tag_history_limit INTEGER NOT NULL,
  retain_referrers INTEGER NOT NULL DEFAULT 1,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  deleted_tag_history_seconds INTEGER NOT NULL DEFAULT 2592000,
  recent_manual_tag_revisions INTEGER NOT NULL DEFAULT 10,
  CHECK(untagged_grace_seconds >= 0),
  CHECK(tag_history_limit >= 0),
  CHECK(retain_referrers IN(0, 1))
);

CREATE TABLE oci_gc_generations(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  captured_mutation_epoch INTEGER NOT NULL,
  placement_inventory_digest KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  plan_digest KEYTEXT128,
  planned_bytes INTEGER NOT NULL DEFAULT 0,
  planned_objects INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  CHECK(captured_mutation_epoch >= 0),
  CHECK(planned_bytes >= 0 AND planned_objects >= 0),
  CHECK(state IN('marking', 'planned', 'applying', 'complete', 'aborted', 'failed'))
);

CREATE TABLE oci_registry_state(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  mutation_epoch INTEGER NOT NULL DEFAULT 0,
  charged_bytes INTEGER NOT NULL DEFAULT 0,
  charged_objects INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  CHECK(mutation_epoch >= 0),
  CHECK(charged_bytes >= 0 AND charged_objects >= 0)
);

CREATE TABLE oci_quota_reservations(
  id KEYTEXT128 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  owner_kind KEYTEXT16 NOT NULL,
  owner_id KEYTEXT128 NOT NULL,
  reserved_bytes INTEGER NOT NULL,
  reserved_objects INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(owner_kind, owner_id),
  CHECK(owner_kind IN('upload', 'publication', 'catalog')),
  CHECK(reserved_bytes >= 0),
  CHECK(reserved_objects >= 0),
  CHECK(state IN('pending', 'reserved', 'committed', 'released'))
);

CREATE TABLE oci_admin_mutations(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  repository_id INTEGER,
  repository_name KEYTEXT128,
  mutation_kind KEYTEXT32 NOT NULL,
  selector_json LONGTEXT NOT NULL,
  desired_json LONGTEXT NOT NULL,
  confirmation_hash KEYTEXT128 NOT NULL,
  actor_id KEYTEXT128 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  apply_idempotency_key KEYTEXT128,
  expected_resource_version INTEGER,
  state KEYTEXT16 NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  applied_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, actor_id, idempotency_key),
  CHECK(mutation_kind IN(
    'repository.create', 'repository.update', 'repository.delete',
    'tag.set', 'tag.unset', 'retention.set'
  )),
  CHECK((repository_id IS NULL AND mutation_kind IN('repository.create', 'retention.set'))
     OR repository_id IS NOT NULL),
  CHECK((repository_name IS NULL AND mutation_kind = 'retention.set')
     OR repository_name IS NOT NULL),
  CHECK(expected_resource_version IS NULL OR expected_resource_version >= 1),
  CHECK(state IN('planned', 'applied', 'aborted')),
  CHECK(expires_at > created_at),
  CHECK(resource_version >= 1)
);

CREATE TABLE oci_gc_runs(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  actor_id KEYTEXT128 NOT NULL,
  plan_idempotency_key KEYTEXT128 NOT NULL,
  apply_idempotency_key KEYTEXT128,
  state KEYTEXT16 NOT NULL,
  captured_mutation_epoch INTEGER NOT NULL,
  applied_mutation_epoch INTEGER,
  policy_resource_version INTEGER NOT NULL,
  policy_digest KEYTEXT128 NOT NULL,
  root_set_digest KEYTEXT128 NOT NULL,
  placement_inventory_digest KEYTEXT128 NOT NULL,
  topology_digest KEYTEXT128 NOT NULL,
  plan_digest KEYTEXT128 NOT NULL,
  confirmation_hash KEYTEXT128 NOT NULL,
  inventory_object_count INTEGER NOT NULL,
  inventory_byte_size INTEGER NOT NULL,
  reachable_object_count INTEGER NOT NULL,
  planned_bytes INTEGER NOT NULL,
  planned_objects INTEGER NOT NULL,
  deleted_object_count INTEGER NOT NULL DEFAULT 0,
  deleted_byte_size INTEGER NOT NULL DEFAULT 0,
  placement_action_count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  applied_at INTEGER,
  finished_at INTEGER,
  last_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, actor_id, plan_idempotency_key),
  UNIQUE(id, registry_id),
  CHECK(state IN('planned', 'applying', 'complete', 'aborted', 'failed')),
  CHECK(captured_mutation_epoch >= 0),
  CHECK(applied_mutation_epoch IS NULL OR applied_mutation_epoch >= 0),
  CHECK(policy_resource_version >= 0),
  CHECK(inventory_object_count >= 0 AND inventory_byte_size >= 0),
  CHECK(reachable_object_count >= 0),
  CHECK(planned_bytes >= 0 AND planned_objects >= 0),
  CHECK(deleted_object_count >= 0 AND deleted_byte_size >= 0),
  CHECK(placement_action_count >= 0),
  CHECK(expires_at > created_at),
  CHECK(resource_version >= 1),
  CHECK((state = 'planned' AND applied_at IS NULL AND finished_at IS NULL)
    OR (state = 'applying' AND applied_at IS NOT NULL AND finished_at IS NULL)
    OR (state IN('complete', 'aborted', 'failed') AND finished_at IS NOT NULL))
);

CREATE TABLE oci_registry_purge_fences(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  actor_id KEYTEXT128 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  registry_resource_version INTEGER NOT NULL,
  captured_mutation_epoch INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  created_at INTEGER NOT NULL,
  aborted_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, actor_id, idempotency_key),
  CHECK(registry_resource_version >= 1),
  CHECK(captured_mutation_epoch >= 0),
  CHECK(state IN('collecting', 'aborted')),
  CHECK((state = 'collecting' AND aborted_at IS NULL)
    OR (state = 'aborted' AND aborted_at IS NOT NULL)),
  CHECK(resource_version >= 1)
);

CREATE TABLE oci_registry_purge_fence_plans(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  action KEYTEXT16 NOT NULL,
  actor_id KEYTEXT128 NOT NULL,
  plan_idempotency_key KEYTEXT128 NOT NULL,
  apply_idempotency_key KEYTEXT128,
  expected_resource_version INTEGER NOT NULL,
  captured_mutation_epoch INTEGER NOT NULL,
  confirmation_hash KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  applied_at INTEGER,
  finished_at INTEGER,
  last_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, actor_id, plan_idempotency_key),
  CHECK(action IN('begin', 'abort')),
  CHECK(expected_resource_version >= 1),
  CHECK(captured_mutation_epoch >= 0),
  CHECK(state IN('planned', 'applied', 'failed')),
  CHECK(expires_at > created_at),
  CHECK(resource_version >= 1)
);

CREATE TABLE delivery_workflows (
  workflow_id KEYTEXT64 PRIMARY KEY,
  owner_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key),
  registry_id INTEGER REFERENCES registries(id),
  cache_id INTEGER REFERENCES binary_caches(id),
  intent_json LONGTEXT NOT NULL,
  progress_json LONGTEXT NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK ((registry_id IS NOT NULL AND cache_id IS NULL)
      OR (registry_id IS NULL AND cache_id IS NOT NULL))
);

CREATE INDEX delivery_workflows_registry ON delivery_workflows(registry_id,
  workflow_id);

CREATE INDEX delivery_workflows_cache ON delivery_workflows(cache_id,
  workflow_id);

CREATE TABLE release_browse_catalogs(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  source_commit KEYTEXT64 NOT NULL,
  packages_json TEXT NOT NULL,
  content_digest KEYTEXT64 NOT NULL,
  package_count INTEGER NOT NULL,
  documentation_count INTEGER NOT NULL,
  default_release KEYTEXT255,
  PRIMARY KEY(registry_id, source_commit)
);

CREATE TABLE release_browse_notes(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  tag_oid KEYTEXT64 NOT NULL,
  body TEXT NOT NULL,
  PRIMARY KEY(registry_id, tag_oid)
);

CREATE TABLE release_records(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  tag_oid KEYTEXT64 NOT NULL,
  record_json LONGTEXT NOT NULL,
  PRIMARY KEY(registry_id, tag_oid)
);

CREATE TABLE package_versions(
  id INTEGER PRIMARY KEY,
  package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
  version TEXT NOT NULL,
  previous TEXT,
  UNIQUE(package_id, version)
);

CREATE TABLE channel_partitions(
  channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bucket INTEGER NOT NULL,
  release KEYTEXT255 NOT NULL,
  PRIMARY KEY(channel_id, bucket)
);

CREATE TABLE signing_key_usages(
  id INTEGER PRIMARY KEY,
  stable_id KEYTEXT64 NOT NULL UNIQUE,
  consumer_stable_id KEYTEXT64 NOT NULL,
  consumer_kind TEXT NOT NULL,
  consumer_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  consumer_name TEXT,
  purpose TEXT NOT NULL,
  signing_key_id KEYTEXT64 NOT NULL,
  signing_key_generation INTEGER NOT NULL,
  state TEXT NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(consumer_stable_id, purpose),
  FOREIGN KEY(signing_key_id, signing_key_generation)
    REFERENCES signing_key_generations(signing_key_id, generation)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CHECK(purpose IN('registry_publication', 'narinfo', 'channel_frontier')),
  CHECK(state IN('active', 'detached')),
  CHECK(
    (consumer_kind = 'registry' AND purpose = 'registry_publication'
      AND consumer_name IS NULL)
    OR (consumer_kind = 'binary_cache' AND purpose = 'narinfo'
      AND consumer_name IS NULL)
    OR (consumer_kind = 'channel' AND purpose = 'channel_frontier'
      AND consumer_name IS NOT NULL)
  )
);

CREATE TABLE binding_credential_heads(
  binding_id INTEGER NOT NULL,
  purpose KEYTEXT16 NOT NULL,
  current_generation INTEGER NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(binding_id, purpose),
  FOREIGN KEY(binding_id, purpose, current_generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
);

CREATE TABLE registry_publication_state(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id),
  current_publication_id KEYTEXT64,
  next_ordinal INTEGER NOT NULL DEFAULT 1,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  CHECK(next_ordinal > 0),
  FOREIGN KEY(current_publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id)
);

CREATE TABLE registry_index_publication_state(
  registry_id INTEGER PRIMARY KEY REFERENCES registry_index(registry_id),
  publication_id KEYTEXT64 NOT NULL,
  FOREIGN KEY(publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id)
);

CREATE TABLE binding_write_revisions(
  binding_id INTEGER NOT NULL REFERENCES bindings(id) ON DELETE CASCADE ON UPDATE RESTRICT,
  revision INTEGER NOT NULL,
  write_credential_version_ref KEYTEXT128 NOT NULL,
  writes_supported INTEGER NOT NULL,
  conditional_writes_supported INTEGER NOT NULL,
  revision_fingerprint KEYTEXT128 NOT NULL,
  capability_fingerprint KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  write_credential_purpose KEYTEXT16 NOT NULL DEFAULT 'write',
  write_credential_generation INTEGER NOT NULL,
  PRIMARY KEY(binding_id, revision),
  UNIQUE(binding_id, revision_fingerprint),
  CHECK(revision > 0),
  CHECK(write_credential_purpose = 'write'),
  CHECK(writes_supported IN(0, 1)),
  CHECK(conditional_writes_supported IN(0, 1)),
  CHECK(conditional_writes_supported = 0 OR writes_supported = 1),
  FOREIGN KEY(binding_id, write_credential_purpose, write_credential_generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
  ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE surface_placements(
  id INTEGER PRIMARY KEY,
  registry_id INTEGER REFERENCES registries(id) ON DELETE CASCADE,
  cache_id INTEGER REFERENCES binary_caches(id) ON DELETE CASCADE,
  name KEYTEXT64 NOT NULL,
  binding_id INTEGER NOT NULL REFERENCES bindings(id),
  consumer_scope_key KEYTEXT64 NOT NULL,
  binding_grant_generation INTEGER NOT NULL,
  binding_grant_state KEYTEXT16 NOT NULL DEFAULT 'active',
  prefix KEYTEXT512 NOT NULL,
  kind KEYTEXT32 NOT NULL,
  desired_state KEYTEXT32 NOT NULL,
  desired_read_enabled INTEGER NOT NULL DEFAULT 1,
  read_order INTEGER NOT NULL DEFAULT 0,
  hash_range_start INTEGER,
  hash_range_end INTEGER,
  write_spec_version INTEGER NOT NULL DEFAULT 1,
  requires_conditional_writes INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK(kind IN('complete', 'shard', 'archive')),
  CHECK(desired_state IN('active', 'draining', 'offline')),
  CHECK(desired_read_enabled IN(0, 1)),
  CHECK((kind = 'shard'
AND hash_range_start IS NOT NULL AND hash_range_end IS NOT NULL
AND hash_range_start >= 0 AND hash_range_start < hash_range_end
AND hash_range_end <= 65536)
OR(kind <> 'shard'
AND hash_range_start IS NULL AND hash_range_end IS NULL)),
  CHECK(kind <> 'archive' OR desired_read_enabled = 0),
  CHECK(write_spec_version > 0),
  CHECK(requires_conditional_writes IN(0, 1)),
  UNIQUE(binding_id, prefix),
  UNIQUE(registry_id, name),
  UNIQUE(cache_id, name),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id),
  UNIQUE(id, kind),
  UNIQUE(id, registry_id, kind),
  UNIQUE(id, cache_id, kind),
  UNIQUE(id, registry_id, kind, hash_range_start, hash_range_end),
  UNIQUE(id, cache_id, kind, hash_range_start, hash_range_end),
  UNIQUE(id, registry_id, write_spec_version),
  UNIQUE(id, cache_id, write_spec_version),
  UNIQUE(id, binding_id),
  UNIQUE(id, binding_id, prefix),
  UNIQUE(id, binding_id, write_spec_version)
  ,
  FOREIGN KEY(binding_id, consumer_scope_key, binding_grant_generation, binding_grant_state)
  REFERENCES binding_consumer_scopes(binding_id, consumer_scope_key, grant_generation, state)
  ON DELETE RESTRICT ON UPDATE RESTRICT,
  CHECK(binding_grant_state = 'active')
);

CREATE TABLE network_policy_defaults(
  boundary_id KEYTEXT64 PRIMARY KEY REFERENCES network_policies(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL DEFAULT 'active',
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  UNIQUE(boundary_id, revision, state),
  FOREIGN KEY(boundary_id, revision, state)
  REFERENCES network_policy_revision_lifecycle(boundary_id, revision, state),
  CHECK(state = 'active')
);

CREATE TABLE placement_policy_revisions(
  id KEYTEXT64 PRIMARY KEY,
  policy_id KEYTEXT64 NOT NULL REFERENCES placement_policies(id) ON DELETE CASCADE,
  registry_id INTEGER REFERENCES registries(id) ON DELETE CASCADE,
  cache_id INTEGER REFERENCES binary_caches(id) ON DELETE CASCADE,
  consumer_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  revision INTEGER NOT NULL,
  kind KEYTEXT32 NOT NULL,
  local_boundary_id KEYTEXT64,
  local_boundary_revision INTEGER,
  allow_remote_fallback INTEGER,
  hash_rule KEYTEXT32,
  retry_on_json LONGTEXT NOT NULL,
  state KEYTEXT16 NOT NULL,
  expected_group_count INTEGER NOT NULL,
  expected_member_count INTEGER NOT NULL,
  build_version INTEGER NOT NULL DEFAULT 0,
  content_digest KEYTEXT128,
  created_by KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  published_at INTEGER,
  error LONGTEXT,
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK(revision > 0),
  CHECK(expected_group_count > 0 AND expected_member_count > 0),
  CHECK(build_version >= 0),
  CHECK(kind IN('ordered_failover', 'local_then_remote', 'hash_partition')),
  CHECK((kind = 'ordered_failover' AND local_boundary_id IS NULL
AND local_boundary_revision IS NULL AND allow_remote_fallback IS NULL
AND hash_rule IS NULL)
OR(kind = 'local_then_remote' AND local_boundary_id IS NOT NULL
AND local_boundary_revision IS NOT NULL AND allow_remote_fallback IN(0, 1)
AND hash_rule IS NULL)
OR(kind = 'hash_partition' AND local_boundary_id IS NULL
AND local_boundary_revision IS NULL AND allow_remote_fallback IS NULL
AND hash_rule = 'hash_range_v1')),
  CHECK((state = 'building' AND content_digest IS NULL
AND published_at IS NULL AND error IS NULL)
OR(state = 'published' AND content_digest IS NOT NULL
AND published_at IS NOT NULL AND error IS NULL)
OR(state = 'failed' AND content_digest IS NULL
AND published_at IS NULL AND error IS NOT NULL)),
  UNIQUE(policy_id, revision),
  UNIQUE(id, policy_id, registry_id),
  UNIQUE(id, policy_id, cache_id),
  UNIQUE(id, policy_id, state),
  UNIQUE(id, policy_id, registry_id, state),
  UNIQUE(id, policy_id, cache_id, state),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id),
  UNIQUE(id, registry_id, kind),
  UNIQUE(id, cache_id, kind),
  UNIQUE(id, registry_id, state),
  UNIQUE(id, cache_id, state),
  UNIQUE(id, build_version, state),
  FOREIGN KEY(policy_id, registry_id) REFERENCES placement_policies(id, registry_id),
  FOREIGN KEY(policy_id, cache_id) REFERENCES placement_policies(id, cache_id),
  FOREIGN KEY(registry_id, consumer_scope_key) REFERENCES registries(id, owner_scope_key),
  FOREIGN KEY(cache_id, consumer_scope_key) REFERENCES binary_caches(id, owner_scope_key),
  FOREIGN KEY(local_boundary_id, local_boundary_revision)
  REFERENCES network_policy_revisions(boundary_id, revision),
  FOREIGN KEY(local_boundary_id, consumer_scope_key)
  REFERENCES network_policy_consumer_scopes(boundary_id, consumer_scope_key)
);

CREATE TABLE surface_objects(
  id INTEGER PRIMARY KEY,
  registry_id INTEGER REFERENCES registries(id) ON DELETE CASCADE,
  cache_id INTEGER REFERENCES binary_caches(id) ON DELETE CASCADE,
  object_key KEYTEXT512 NOT NULL,
  object_kind KEYTEXT32 NOT NULL,
  partition_key BLOB,
  content_hash KEYTEXT128,
  size INTEGER,
  mutable_publication_id KEYTEXT64,
  lifecycle_state KEYTEXT32 NOT NULL DEFAULT 'active',
  tombstoned_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK((object_kind = 'immutable' AND partition_key IS NOT NULL
AND length(partition_key) = 32 AND mutable_publication_id IS NULL)
OR(object_kind = 'mutable_pointer' AND registry_id IS NOT NULL
AND partition_key IS NULL AND mutable_publication_id IS NOT NULL)),
  CHECK((lifecycle_state = 'active' AND tombstoned_at IS NULL)
OR(lifecycle_state = 'tombstoned' AND tombstoned_at IS NOT NULL)),
  UNIQUE(registry_id, object_key),
  UNIQUE(cache_id, object_key),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id),
  FOREIGN KEY(mutable_publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id)
);

CREATE INDEX surface_objects_partition_key_idx ON surface_objects(partition_key);

CREATE TABLE registry_system_images(
  registry_id INTEGER NOT NULL,
  release KEYTEXT255 NOT NULL,
  source_commit KEYTEXT128 NOT NULL,
  verified_tag_oid KEYTEXT128 NOT NULL,
  catalog_digest KEYTEXT128 NOT NULL,
  package_name KEYTEXT255 NOT NULL,
  platform KEYTEXT255 NOT NULL,
  format KEYTEXT32 NOT NULL,
  delivery LONGTEXT NOT NULL,
  PRIMARY KEY(registry_id, release, package_name, platform, format),
  FOREIGN KEY(registry_id, release)
  REFERENCES releases(registry_id, semver) ON DELETE CASCADE,
  CHECK(length(source_commit) > 0),
  CHECK(length(verified_tag_oid) > 0),
  CHECK(length(catalog_digest) = 64)
);

CREATE TABLE cache_retention_refreshes(
  refresh_id KEYTEXT64 PRIMARY KEY,
  subscription_id INTEGER NOT NULL,
  cache_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  parent_refresh_id KEYTEXT64,
  expected_parent_refresh_id KEYTEXT64,
  expected_subscription_version INTEGER NOT NULL,
  expected_cache_epoch INTEGER NOT NULL,
  selector_digest KEYTEXT128 NOT NULL,
  registry_source_revision KEYTEXT128 NOT NULL,
  registry_index_generation INTEGER NOT NULL,
  registry_index_digest KEYTEXT128 NOT NULL,
  state KEYTEXT32 NOT NULL DEFAULT 'building',
  error LONGTEXT,
  started_at INTEGER NOT NULL,
  activated_at INTEGER,
  parent_grace_until INTEGER,
  finished_at INTEGER,
  expected_reason_count INTEGER NOT NULL,
  actual_reason_count INTEGER NOT NULL DEFAULT 0,
  UNIQUE(refresh_id, subscription_id, cache_id, registry_id),
  CHECK(expected_subscription_version > 0),
  CHECK(expected_cache_epoch >= 0),
  CHECK(registry_index_generation > 0),
  CHECK(expected_reason_count >= 0),
  CHECK(actual_reason_count >= 0),
  CHECK(state IN('building', 'complete', 'failed')),
  CHECK((state = 'building' AND finished_at IS NULL AND error IS NULL)
OR(state = 'complete' AND finished_at IS NOT NULL
AND activated_at IS NOT NULL AND parent_grace_until >= activated_at
AND actual_reason_count = expected_reason_count AND error IS NULL)
OR(state = 'failed' AND finished_at IS NOT NULL AND error IS NOT NULL))
  ,
  FOREIGN KEY(subscription_id, cache_id, registry_id)
  REFERENCES cache_retention_subscriptions(id, cache_id, registry_id),
  FOREIGN KEY(parent_refresh_id, subscription_id, cache_id, registry_id)
  REFERENCES cache_retention_refreshes(refresh_id, subscription_id, cache_id, registry_id)
);

CREATE TABLE manual_retention_lease_heads(
  manual_retention_root_id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL,
  current_lease_id KEYTEXT64 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  UNIQUE(manual_retention_root_id, cache_id),
  FOREIGN KEY(manual_retention_root_id, cache_id)
  REFERENCES manual_retention_roots(id, cache_id),
  FOREIGN KEY(current_lease_id, manual_retention_root_id)
  REFERENCES retention_leases(id, manual_retention_root_id)
);

CREATE TABLE endpoint_revisions(
  endpoint_id KEYTEXT64 NOT NULL,
  generation INTEGER NOT NULL,
  network_policy_id KEYTEXT64 NOT NULL,
  boundary_revision INTEGER NOT NULL,
  ingress_kind KEYTEXT16 NOT NULL,
  listener_configuration LONGTEXT NOT NULL,
  tls_configuration LONGTEXT NOT NULL,
  probe_configuration LONGTEXT NOT NULL,
  content_digest KEYTEXT128 NOT NULL,
  created_by KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(endpoint_id, generation),
  UNIQUE(endpoint_id, generation, ingress_kind),
  UNIQUE(endpoint_id, generation, network_policy_id, boundary_revision),
  FOREIGN KEY(endpoint_id, network_policy_id)
  REFERENCES endpoints(id, network_policy_id) ON DELETE CASCADE,
  FOREIGN KEY(network_policy_id, boundary_revision)
  REFERENCES network_policy_revisions(boundary_id, revision),
  CHECK(generation > 0),
  CHECK(ingress_kind IN('hub', 'external', 'layer7'))
);

CREATE TABLE gateway_path_reservations(
  reservation_id KEYTEXT64 PRIMARY KEY,
  gateway_id KEYTEXT64 NOT NULL REFERENCES gateways(id),
  endpoint_id KEYTEXT64 NOT NULL REFERENCES endpoints(id),
  client_base_path KEYTEXT512 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  UNIQUE(endpoint_id, client_base_path),
  UNIQUE(reservation_id, gateway_id, endpoint_id, client_base_path)
);

CREATE TABLE release_artifact_snapshots(
  snapshot_id KEYTEXT64 PRIMARY KEY,
  release_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  source_commit KEYTEXT128 NOT NULL,
  verified_tag_oid KEYTEXT128 NOT NULL,
  verification_record_id KEYTEXT64 NOT NULL,
  manifest_digest KEYTEXT128,
  state KEYTEXT16 NOT NULL,
  complete_slot INTEGER,
  expected_artifact_count INTEGER NOT NULL,
  actual_artifact_count INTEGER NOT NULL,
  started_at INTEGER NOT NULL,
  completed_at INTEGER,
  error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(snapshot_id, release_id, registry_id),
  UNIQUE(release_id, complete_slot),
  CHECK(state IN('building', 'complete', 'failed')),
  CHECK(expected_artifact_count >= 0),
  CHECK(actual_artifact_count >= 0),
  CHECK((state = 'building' AND complete_slot IS NULL
AND manifest_digest IS NULL AND completed_at IS NULL AND error IS NULL)
OR(state = 'complete' AND complete_slot = 1
AND manifest_digest IS NOT NULL AND completed_at IS NOT NULL
AND error IS NULL AND actual_artifact_count = expected_artifact_count)
OR(state = 'failed' AND complete_slot IS NULL
AND completed_at IS NOT NULL AND error IS NOT NULL)),
  FOREIGN KEY(release_id, registry_id) REFERENCES releases(id, registry_id)
);

CREATE TABLE binding_scope_grant_pins(
  pin_id KEYTEXT64 PRIMARY KEY,
  binding_id INTEGER NOT NULL,
  consumer_scope_key KEYTEXT64 NOT NULL,
  grant_generation INTEGER NOT NULL,
  grant_state KEYTEXT16 NOT NULL DEFAULT 'active',
  target_kind KEYTEXT32 NOT NULL,
  target_stable_id KEYTEXT64 NOT NULL,
  target_generation_key INTEGER NOT NULL,
  target_configuration_digest KEYTEXT128 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(binding_id, consumer_scope_key, target_kind, target_stable_id,
target_generation_key, target_configuration_digest),
  FOREIGN KEY(binding_id, consumer_scope_key, grant_generation, grant_state)
  REFERENCES binding_consumer_scopes(binding_id, consumer_scope_key, grant_generation, state),
  CHECK(grant_state = 'active')
);

CREATE TABLE cache_gc_state(
  cache_id INTEGER PRIMARY KEY REFERENCES binary_caches(id) ON DELETE CASCADE,
  epoch INTEGER NOT NULL DEFAULT 0,
  epoch_owner_token KEYTEXT64 NOT NULL,
  root_generation INTEGER NOT NULL DEFAULT 0,
  object_graph_generation INTEGER NOT NULL DEFAULT 0,
  inventory_generation INTEGER NOT NULL,
  topology_generation INTEGER NOT NULL DEFAULT 0,
  destructive_enabled INTEGER NOT NULL DEFAULT 0,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(cache_id, epoch, epoch_owner_token),
  CHECK(epoch >= 0 AND root_generation >= 0
AND object_graph_generation >= 0 AND inventory_generation > 0
AND topology_generation >= 0 AND resource_version > 0),
  CHECK(destructive_enabled IN(0, 1)),
  FOREIGN KEY(cache_id, inventory_generation)
  REFERENCES cache_inventory_generations(cache_id, generation)
);

CREATE TABLE cache_gc_generation_placements(
  cache_id INTEGER NOT NULL,
  generation_id KEYTEXT64 NOT NULL,
  placement_id INTEGER NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  placement_name KEYTEXT64 NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_stable_id KEYTEXT64 NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  prefix KEYTEXT512 NOT NULL,
  placement_kind KEYTEXT32 NOT NULL,
  desired_state KEYTEXT32 NOT NULL,
  write_spec_version INTEGER NOT NULL,
  requires_conditional_writes INTEGER NOT NULL,
  PRIMARY KEY(cache_id, generation_id, placement_id),
  CHECK(placement_resource_version > 0),
  CHECK(binding_resource_version > 0),
  CHECK(write_spec_version > 0),
  CHECK(requires_conditional_writes IN(0, 1)),
  FOREIGN KEY(generation_id, cache_id)
  REFERENCES cache_gc_generations(generation_id, cache_id)
);

CREATE TABLE cache_gc_marks(
  cache_id INTEGER NOT NULL,
  generation_id KEYTEXT64 NOT NULL,
  -- Historical evidence: intentionally survives cache-object tombstone reaping.
  cache_object_id INTEGER NOT NULL,
  PRIMARY KEY(cache_id, generation_id, cache_object_id),
  FOREIGN KEY(generation_id, cache_id)
  REFERENCES cache_gc_generations(generation_id, cache_id)
);

CREATE TABLE cache_gc_generation_coverage_errors(
  cache_id INTEGER NOT NULL,
  generation_id KEYTEXT64 NOT NULL,
  error_id KEYTEXT64 NOT NULL,
  kind KEYTEXT32 NOT NULL,
  store_hash KEYTEXT64,
  referenced_store_hash KEYTEXT64,
  detail LONGTEXT NOT NULL,
  PRIMARY KEY(cache_id, generation_id, error_id),
  CHECK(kind IN('missing_root', 'missing_reference', 'stale_inventory')),
  FOREIGN KEY(generation_id, cache_id)
  REFERENCES cache_gc_generations(generation_id, cache_id)
);

CREATE TABLE cache_gc_plans(
  plan_id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL REFERENCES binary_caches(id) ON DELETE CASCADE,
  generation_id KEYTEXT64 NOT NULL,
  expected_epoch INTEGER NOT NULL,
  input_versions_digest KEYTEXT128 NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  actor_scope_digest KEYTEXT128 NOT NULL,
  confirmation_hash KEYTEXT128 NOT NULL,
  created_by KEYTEXT128 NOT NULL,
  request_idempotency_key KEYTEXT128 NOT NULL,
  request_digest KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  applied_at INTEGER,
  operation_id KEYTEXT64,
  operation_target_kind KEYTEXT32,
  operation_target_stable_id KEYTEXT255,
  UNIQUE(plan_id, cache_id),
  UNIQUE(cache_id, actor_scope_digest, request_idempotency_key),
  CHECK(expected_epoch >= 0),
  CHECK(expires_at > created_at),
  CHECK((applied_at IS NULL AND operation_id IS NULL
AND operation_target_kind IS NULL AND operation_target_stable_id IS NULL)
OR(applied_at IS NOT NULL AND operation_id IS NOT NULL
AND operation_target_kind = 'binary_cache'
AND operation_target_stable_id IS NOT NULL)),
  FOREIGN KEY(generation_id, cache_id)
  REFERENCES cache_gc_generations(generation_id, cache_id),
  FOREIGN KEY(operation_id) REFERENCES topology_operations(operation_id),
  FOREIGN KEY(operation_id, operation_target_kind, operation_target_stable_id)
  REFERENCES topology_operations(operation_id, primary_target_kind, primary_target_stable_id),
  FOREIGN KEY(cache_id, operation_target_stable_id)
  REFERENCES binary_caches(id, stable_id)
);

CREATE TABLE refresh_tokens(
  hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX refresh_tokens_family ON refresh_tokens(family_id);

CREATE TABLE registry_publication_manifest_sessions(
  publication_id KEYTEXT64 PRIMARY KEY REFERENCES registry_publications(publication_id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  lease_token KEYTEXT64 NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  expected_object_count INTEGER NOT NULL,
  admitted_object_count INTEGER NOT NULL DEFAULT 0,
  next_chunk_index INTEGER NOT NULL DEFAULT 0,
  state KEYTEXT16 NOT NULL,
  lease_expires_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK(expected_object_count > 0),
  CHECK(admitted_object_count >= 0 AND admitted_object_count <= expected_object_count),
  CHECK(next_chunk_index >= 0),
  CHECK(state IN('accepting', 'sealed')),
  CHECK(resource_version > 0),
  CHECK((state = 'accepting' AND lease_expires_at IS NOT NULL)
     OR (state = 'sealed' AND lease_expires_at IS NULL)),
  FOREIGN KEY(publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id)
);

CREATE TABLE package_documentation_search(
  registry_id INTEGER NOT NULL,
  package_name TEXT NOT NULL,
  package_version TEXT NOT NULL,
  platform TEXT NOT NULL,
  kind KEYTEXT16 NOT NULL,
  document_key TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  terms LONGTEXT NOT NULL,
  PRIMARY KEY(
    registry_id, package_name, package_version, platform, kind, document_key
  ),
  FOREIGN KEY(registry_id, package_name, package_version, platform)
    REFERENCES package_documentation(
      registry_id, package_name, package_version, platform
    ) ON DELETE CASCADE,
  CHECK(kind IN('package', 'option', 'service', 'credential', 'capability'))
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
  staging_receipt_digest KEYTEXT128 NOT NULL,
  staging_receipt_json TEXT NOT NULL,
  qualification_digest KEYTEXT128 NOT NULL UNIQUE,
  receipt_json TEXT NOT NULL,
  qualified_at INTEGER NOT NULL
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

CREATE TABLE oci_tag_history(
  id KEYTEXT64 PRIMARY KEY,
  repository_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  name KEYTEXT128 NOT NULL,
  prior_digest KEYTEXT128,
  next_digest KEYTEXT128,
  source_kind KEYTEXT16 NOT NULL,
  actor_id KEYTEXT128 NOT NULL,
  changed_at INTEGER NOT NULL,
  tag_resource_version INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  CHECK(prior_digest IS NOT NULL OR next_digest IS NOT NULL),
  CHECK(source_kind IN('manual', 'release', 'channel', 'retention'))
);

CREATE TABLE oci_publications(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL,
  target_tag KEYTEXT128,
  root_digest KEYTEXT128 NOT NULL,
  source_kind KEYTEXT16 NOT NULL,
  state KEYTEXT16 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  committed_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, idempotency_key),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  CHECK(source_kind IN('manual', 'release')),
  CHECK(state IN('preparing', 'committing', 'ready', 'aborted', 'failed'))
);

CREATE TABLE oci_publication_sessions(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL,
  writer_id KEYTEXT128 NOT NULL,
  token_id KEYTEXT128 NOT NULL,
  target_tag KEYTEXT128,
  expected_tag_version INTEGER,
  expected_tag_digest KEYTEXT128,
  root_digest KEYTEXT128 NOT NULL,
  catalog_digest KEYTEXT128 NOT NULL,
  release_tag KEYTEXT255,
  sidecar_sha256 KEYTEXT128,
  confirmation_hash KEYTEXT128 NOT NULL,
  topology_digest KEYTEXT128 NOT NULL,
  required_placement_count INTEGER NOT NULL,
  source_kind KEYTEXT16 NOT NULL,
  state KEYTEXT16 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  commit_idempotency_key KEYTEXT128,
  abort_idempotency_key KEYTEXT128,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  committed_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, writer_id, idempotency_key),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  CHECK(source_kind IN('manual', 'release', 'channel')),
  CHECK((source_kind = 'manual' AND release_tag IS NULL AND sidecar_sha256 IS NULL)
     OR (source_kind IN('release', 'channel')
         AND release_tag IS NOT NULL AND sidecar_sha256 IS NOT NULL)),
  CHECK(state IN('preparing', 'committing', 'ready', 'aborted', 'failed')),
  CHECK(required_placement_count > 0),
  CHECK(expected_tag_version IS NULL OR expected_tag_version >= 1)
);

CREATE TABLE oci_repository_metadata(
  repository_id INTEGER PRIMARY KEY,
  registry_id INTEGER NOT NULL,
  description LONGTEXT NOT NULL DEFAULT (''),
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  UNIQUE(registry_id, repository_id),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  CHECK(resource_version >= 1),
  CHECK(length(description) <= 4096)
);

CREATE TABLE oci_gc_registry_locks(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  run_id KEYTEXT64 NOT NULL UNIQUE REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  acquired_at INTEGER NOT NULL
);

CREATE TABLE oci_gc_roots(
  run_id KEYTEXT64 NOT NULL REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  root_kind KEYTEXT32 NOT NULL,
  digest KEYTEXT128 NOT NULL,
  source_id KEYTEXT512 NOT NULL,
  repository_id INTEGER,
  PRIMARY KEY(run_id, root_kind, digest, source_id),
  CHECK(root_kind IN(
    'tag', 'signed_release', 'lease', 'upload', 'publication',
    'tag_history', 'referrer'
  ))
);

CREATE INDEX oci_gc_roots_digest_idx ON oci_gc_roots(run_id,
  digest);

CREATE TABLE oci_gc_blockers(
  run_id KEYTEXT64 NOT NULL REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  blocker_kind KEYTEXT64 NOT NULL,
  digest KEYTEXT128,
  detail LONGTEXT NOT NULL,
  PRIMARY KEY(run_id, ordinal),
  CHECK(ordinal >= 0)
);

CREATE TABLE oci_gc_candidates(
  run_id KEYTEXT64 NOT NULL REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  surface_object_id INTEGER NOT NULL,
  catalog_object_resource_version INTEGER NOT NULL,
  repository_count INTEGER NOT NULL,
  eligible_at INTEGER NOT NULL,
  state KEYTEXT32 NOT NULL,
  finalized_at INTEGER,
  last_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(run_id, digest),
  FOREIGN KEY(run_id, registry_id)
  REFERENCES oci_gc_runs(id, registry_id) ON DELETE CASCADE,
  CHECK(byte_size >= 0),
  CHECK(catalog_object_resource_version >= 1),
  CHECK(repository_count >= 0),
  CHECK(state IN('planned', 'deleting', 'physically_absent', 'complete', 'failed')),
  CHECK(resource_version >= 1)
);

CREATE INDEX oci_gc_candidates_state_idx ON oci_gc_candidates(run_id,
  state,
  digest);

CREATE TABLE oci_gc_placement_snapshots(
  run_id KEYTEXT64 NOT NULL REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  placement_name KEYTEXT64 NOT NULL,
  placement_prefix KEYTEXT512 NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  placement_write_spec_version INTEGER NOT NULL,
  placement_observation_version INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  delete_credential_purpose KEYTEXT16,
  delete_credential_generation INTEGER,
  delete_capability_fingerprint KEYTEXT128 NOT NULL,
  delete_capability_resource_version INTEGER NOT NULL,
  delete_capability_observed_at INTEGER NOT NULL,
  inventory_generation_id KEYTEXT64 NOT NULL,
  inventory_digest KEYTEXT128 NOT NULL,
  inventory_observed_at INTEGER NOT NULL,
  PRIMARY KEY(run_id, placement_id),
  CHECK(placement_resource_version >= 1),
  CHECK(placement_write_spec_version >= 1),
  CHECK(placement_observation_version >= 1),
  CHECK(binding_resource_version >= 1),
  CHECK(binding_write_revision >= 1),
  CHECK(delete_capability_resource_version >= 1),
  CHECK((delete_credential_purpose IS NULL
      AND delete_credential_generation IS NULL)
    OR (delete_credential_purpose = 'delete'
      AND delete_credential_generation >= 1))
);

CREATE TABLE oci_gc_credential_holds(
  run_id KEYTEXT64 NOT NULL REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  binding_id INTEGER NOT NULL,
  purpose KEYTEXT16 NOT NULL,
  generation INTEGER NOT NULL,
  PRIMARY KEY(run_id, binding_id, purpose, generation),
  FOREIGN KEY(binding_id, purpose, generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
  ON DELETE RESTRICT,
  CHECK(purpose = 'delete'),
  CHECK(generation >= 1)
);

CREATE TABLE oci_gc_snapshot_lease_holds(
  run_id KEYTEXT64 NOT NULL,
  registry_id INTEGER NOT NULL,
  snapshot_digest KEYTEXT64 NOT NULL,
  retired_at INTEGER NOT NULL,
  PRIMARY KEY(run_id, snapshot_digest),
  FOREIGN KEY(run_id, registry_id)
  REFERENCES oci_gc_runs(id, registry_id) ON DELETE CASCADE,
  CHECK(length(snapshot_digest) = 64)
);

CREATE TABLE delivery_workflow_resumptions (
  actor_kind KEYTEXT32 NOT NULL,
  actor_id INTEGER NOT NULL,
  request_key KEYTEXT128 NOT NULL,
  workflow_id KEYTEXT64 NOT NULL REFERENCES delivery_workflows(workflow_id),
  expected_resource_version INTEGER NOT NULL,
  completed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(actor_kind, actor_id, request_key),
  CHECK(completed IN (0, 1))
);

CREATE TABLE release_browse_tree_nodes(
  registry_id INTEGER NOT NULL,
  source_commit KEYTEXT64 NOT NULL,
  node_key KEYTEXT64 NOT NULL,
  parent_key KEYTEXT64,
  path_json TEXT NOT NULL,
  label KEYTEXT1024 NOT NULL,
  sort_key KEYTEXT1024 NOT NULL,
  child_count INTEGER NOT NULL,
  entry_count INTEGER NOT NULL,
  PRIMARY KEY(registry_id, source_commit, node_key),
  FOREIGN KEY(registry_id, source_commit)
    REFERENCES release_browse_catalogs(registry_id, source_commit) ON DELETE CASCADE
);

CREATE TABLE release_browse_tree_ancestors(
  registry_id INTEGER NOT NULL,
  source_commit KEYTEXT64 NOT NULL,
  ancestor_key KEYTEXT64 NOT NULL,
  node_key KEYTEXT64 NOT NULL,
  PRIMARY KEY(registry_id, source_commit, ancestor_key, node_key),
  FOREIGN KEY(registry_id, source_commit)
    REFERENCES release_browse_catalogs(registry_id, source_commit) ON DELETE CASCADE
);

CREATE TABLE version_platforms(
  id INTEGER PRIMARY KEY,
  version_id INTEGER NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
  platform TEXT NOT NULL,
  store_path TEXT NOT NULL,
  nar_hash TEXT NOT NULL,
  nar_size INTEGER NOT NULL,
  closure_size INTEGER NOT NULL,
  refs LONGTEXT NOT NULL, -- JSON array of store hashes(unbounded; never truncate)
  images LONGTEXT NOT NULL,
  source_drv TEXT NOT NULL DEFAULT '', -- JSON array of {format,store_path,nar_hash,nar_size}(unbounded)
  UNIQUE(version_id, platform)
);

CREATE TABLE binding_write_state(
  binding_id INTEGER PRIMARY KEY REFERENCES bindings(id) ON DELETE CASCADE ON UPDATE RESTRICT,
  current_write_revision INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(binding_id, current_write_revision)
  REFERENCES binding_write_revisions(binding_id, revision)
  ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE binding_write_observations(
  binding_id INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  state KEYTEXT32 NOT NULL,
  validated_at INTEGER,
  error LONGTEXT,
  observation_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(binding_id, revision),
  FOREIGN KEY(binding_id, revision)
  REFERENCES binding_write_revisions(binding_id, revision)
  ON DELETE CASCADE ON UPDATE RESTRICT,
  CHECK(state IN('unknown', 'validating', 'valid', 'invalid')),
  CHECK((state IN('unknown', 'validating') AND validated_at IS NULL)
OR(state IN('valid', 'invalid') AND validated_at IS NOT NULL)),
  CHECK(state = 'invalid' OR error IS NULL),
  CHECK(observation_version > 0)
);

CREATE TABLE surface_placement_observations(
  placement_id INTEGER PRIMARY KEY REFERENCES surface_placements(id) ON DELETE CASCADE ON UPDATE RESTRICT,
  state KEYTEXT32 NOT NULL,
  completeness KEYTEXT32 NOT NULL,
  observed_at INTEGER NOT NULL,
  observation_version INTEGER NOT NULL DEFAULT 1,
  CHECK(state IN('provisioning', 'syncing', 'ready', 'degraded', 'offline')),
  CHECK(completeness IN('complete', 'partial', 'unknown'))
);

CREATE TABLE registry_placement_publication_watermarks(
  placement_id INTEGER PRIMARY KEY REFERENCES surface_placements(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  mutable_publication_id KEYTEXT64,
  pending_publication_id KEYTEXT64,
  observed_at INTEGER NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK(mutable_publication_id IS NULL OR pending_publication_id IS NULL),
  FOREIGN KEY(placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id) ON DELETE CASCADE ON UPDATE RESTRICT,
  FOREIGN KEY(mutable_publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(pending_publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE surface_placement_write_capabilities(
  placement_id INTEGER NOT NULL,
  placement_write_spec_version INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(placement_id, placement_write_spec_version, binding_write_revision),
  FOREIGN KEY(placement_id, binding_id, placement_write_spec_version)
  REFERENCES surface_placements(id, binding_id, write_spec_version)
  ON DELETE CASCADE ON UPDATE RESTRICT,
  FOREIGN KEY(binding_id, binding_write_revision)
  REFERENCES binding_write_revisions(binding_id, revision)
  ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE placement_policy_heads(
  policy_id KEYTEXT64 PRIMARY KEY REFERENCES placement_policies(id) ON DELETE CASCADE,
  current_revision_id KEYTEXT64,
  current_revision_state KEYTEXT16,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  CHECK((current_revision_id IS NULL AND current_revision_state IS NULL)
OR(current_revision_id IS NOT NULL AND current_revision_state = 'published')),
  UNIQUE(policy_id, resource_version),
  FOREIGN KEY(current_revision_id, policy_id, current_revision_state)
  REFERENCES placement_policy_revisions(id, policy_id, state)
);

CREATE TABLE placement_policy_replica_groups(
  policy_revision_id KEYTEXT64 NOT NULL,
  registry_id INTEGER,
  cache_id INTEGER,
  group_id KEYTEXT64 NOT NULL,
  group_order INTEGER NOT NULL,
  policy_kind KEYTEXT32 NOT NULL,
  purpose KEYTEXT32 NOT NULL,
  range_start INTEGER,
  range_end INTEGER,
  PRIMARY KEY(policy_revision_id, group_id),
  UNIQUE(policy_revision_id, group_order),
  UNIQUE(policy_revision_id, group_id, registry_id),
  UNIQUE(policy_revision_id, group_id, cache_id),
  UNIQUE(policy_revision_id, group_id, registry_id, policy_kind, purpose),
  UNIQUE(policy_revision_id, group_id, cache_id, policy_kind, purpose),
  UNIQUE(policy_revision_id, group_id, registry_id, policy_kind, purpose,
range_start, range_end),
  UNIQUE(policy_revision_id, group_id, cache_id, policy_kind, purpose,
range_start, range_end),
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK(group_order >= 0),
  CHECK((policy_kind = 'ordered_failover' AND purpose = 'ordered'
AND range_start IS NULL AND range_end IS NULL)
OR(policy_kind = 'local_then_remote' AND purpose IN('local', 'remote')
AND range_start IS NULL AND range_end IS NULL)
OR(policy_kind = 'hash_partition' AND purpose = 'hash_range'
AND range_start IS NOT NULL AND range_end IS NOT NULL
AND range_start >= 0 AND range_start < range_end AND range_end <= 65536)
OR(policy_kind = 'hash_partition' AND purpose = 'complete_fallback'
AND range_start IS NULL AND range_end IS NULL)),
  FOREIGN KEY(policy_revision_id, registry_id, policy_kind)
  REFERENCES placement_policy_revisions(id, registry_id, kind),
  FOREIGN KEY(policy_revision_id, cache_id, policy_kind)
  REFERENCES placement_policy_revisions(id, cache_id, kind)
);

CREATE TABLE placement_equivalences(
  id KEYTEXT64 PRIMARY KEY,
  placement_a_id INTEGER NOT NULL REFERENCES surface_placements(id) ON DELETE CASCADE,
  placement_b_id INTEGER NOT NULL REFERENCES surface_placements(id) ON DELETE CASCADE,
  physical_identity_fingerprint KEYTEXT128 NOT NULL,
  evidence_digest KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL DEFAULT 'active',
  creation_token KEYTEXT64 NOT NULL UNIQUE,
  confirmed_by KEYTEXT128 NOT NULL,
  confirmed_at INTEGER NOT NULL,
  validation_revision KEYTEXT128 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK(state = 'active'),
  CHECK(placement_a_id < placement_b_id),
  UNIQUE(placement_a_id, placement_b_id)
);

CREATE TABLE registry_image_roots(
  registry_id INTEGER NOT NULL,
  release KEYTEXT255 NOT NULL,
  surface_object_id INTEGER NOT NULL,
  object_role KEYTEXT16 NOT NULL,
  expected_hash KEYTEXT128 NOT NULL,
  expected_size INTEGER NOT NULL,
  CHECK(object_role IN('disk', 'image_info')),
  CHECK(expected_size > 0),
  PRIMARY KEY(registry_id, release, surface_object_id, object_role),
  FOREIGN KEY(registry_id, release)
  REFERENCES releases(registry_id, semver) ON DELETE CASCADE,
  FOREIGN KEY(surface_object_id, registry_id)
  REFERENCES surface_objects(id, registry_id) ON DELETE CASCADE
);

CREATE TABLE image_snapshot_references(
  digest KEYTEXT64 NOT NULL REFERENCES image_snapshots(digest) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  placement_id INTEGER NOT NULL REFERENCES surface_placements(id) ON DELETE CASCADE,
  object_key KEYTEXT512 NOT NULL,
  PRIMARY KEY(digest, registry_id, placement_id, object_key)
);

CREATE TABLE object_placements(
  surface_object_id INTEGER NOT NULL,
  cache_id INTEGER,
  registry_id INTEGER,
  placement_id INTEGER NOT NULL,
  state KEYTEXT32 NOT NULL,
  observed_hash KEYTEXT128,
  observed_size INTEGER,
  etag KEYTEXT255,
  observed_inventory_generation INTEGER NOT NULL,
  observed_at INTEGER NOT NULL,
  catalog_object_resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK(state IN('present', 'copying', 'missing', 'corrupt', 'deleting')),
  CHECK(observed_inventory_generation > 0),
  PRIMARY KEY(surface_object_id, placement_id),
  FOREIGN KEY(surface_object_id, cache_id)
  REFERENCES surface_objects(id, cache_id),
  FOREIGN KEY(surface_object_id, registry_id)
  REFERENCES surface_objects(id, registry_id),
  FOREIGN KEY(placement_id, cache_id)
  REFERENCES surface_placements(id, cache_id),
  FOREIGN KEY(placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id)
);

CREATE TABLE registry_publication_objects(
  publication_id KEYTEXT64 NOT NULL REFERENCES registry_publications(publication_id),
  registry_id INTEGER NOT NULL REFERENCES registries(id),
  surface_object_id INTEGER NOT NULL,
  object_kind KEYTEXT32 NOT NULL,
  expected_hash KEYTEXT128 NOT NULL,
  expected_size INTEGER NOT NULL,
  CHECK(object_kind IN('immutable', 'mutable_pointer')),
  CHECK(expected_size >= 0),
  PRIMARY KEY(publication_id, surface_object_id),
  FOREIGN KEY(publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id),
  FOREIGN KEY(surface_object_id, registry_id)
  REFERENCES surface_objects(id, registry_id)
);

CREATE TABLE registry_publication_placements(
  publication_id KEYTEXT64 NOT NULL REFERENCES registry_publications(publication_id),
  registry_id INTEGER NOT NULL REFERENCES registries(id),
  placement_id INTEGER NOT NULL,
  required INTEGER NOT NULL DEFAULT 1,
  state KEYTEXT32 NOT NULL,
  observed_at INTEGER NOT NULL,
  CHECK(state IN('preparing', 'writing_pointers', 'ready', 'failed', 'retired')),
  PRIMARY KEY(publication_id, placement_id),
  FOREIGN KEY(publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id),
  FOREIGN KEY(placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id)
);

CREATE TABLE cache_population_targets(
  id INTEGER PRIMARY KEY,
  cache_id INTEGER NOT NULL REFERENCES binary_caches(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  trigger_kind KEYTEXT32 NOT NULL,
  required INTEGER NOT NULL DEFAULT 0,
  placement_policy_revision_id KEYTEXT64,
  placement_policy_revision_state KEYTEXT16,
  selector_json LONGTEXT NOT NULL,
  validation_gate KEYTEXT32 NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK(trigger_kind IN('release', 'manual', 'continuous')),
  CHECK(validation_gate IN('none', 'presence', 'integrity')),
  CHECK((placement_policy_revision_id IS NULL
AND placement_policy_revision_state IS NULL)
OR(placement_policy_revision_id IS NOT NULL
AND placement_policy_revision_state = 'published')),
  UNIQUE(cache_id, registry_id, trigger_kind),
  FOREIGN KEY(placement_policy_revision_id, cache_id,
placement_policy_revision_state)
  REFERENCES placement_policy_revisions(id, cache_id, state)
);

CREATE TABLE cache_retention_refresh_heads(
  subscription_id INTEGER PRIMARY KEY,
  cache_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  current_refresh_id KEYTEXT64 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  UNIQUE(subscription_id, cache_id, registry_id),
  FOREIGN KEY(subscription_id, cache_id, registry_id)
  REFERENCES cache_retention_subscriptions(id, cache_id, registry_id),
  FOREIGN KEY(current_refresh_id, subscription_id, cache_id, registry_id)
  REFERENCES cache_retention_refreshes(
refresh_id, subscription_id, cache_id, registry_id)
);

CREATE TABLE cache_root_reasons(
  id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL REFERENCES binary_caches(id),
  registry_id INTEGER REFERENCES registries(id),
  store_hash KEYTEXT64 NOT NULL,
  reason_key KEYTEXT255 NOT NULL,
  source_kind KEYTEXT32 NOT NULL,
  refresh_id KEYTEXT64 REFERENCES cache_retention_refreshes(refresh_id),
  retention_subscription_id INTEGER REFERENCES cache_retention_subscriptions(id),
  manual_retention_root_id KEYTEXT64 REFERENCES manual_retention_roots(id),
  retention_lease_id KEYTEXT64 REFERENCES retention_leases(id),
  release_id INTEGER REFERENCES releases(id),
  channel_id INTEGER REFERENCES channels(id),
  partition_bucket INTEGER,
  source_ref KEYTEXT255 NOT NULL,
  source_revision KEYTEXT128 NOT NULL,
  expires_at INTEGER,
  refreshed_at INTEGER NOT NULL,
  CHECK(source_kind IN('manual', 'lease', 'registry_catalog', 'release', 'channel')),
  CHECK((source_kind = 'manual'
AND registry_id IS NULL AND retention_subscription_id IS NULL
AND refresh_id IS NULL
AND manual_retention_root_id IS NOT NULL
AND retention_lease_id IS NULL AND release_id IS NULL
AND channel_id IS NULL AND partition_bucket IS NULL)
OR(source_kind = 'lease'
AND registry_id IS NULL AND retention_subscription_id IS NULL
AND refresh_id IS NULL
AND manual_retention_root_id IS NOT NULL
AND retention_lease_id IS NOT NULL AND release_id IS NULL
AND channel_id IS NULL AND partition_bucket IS NULL)
OR(source_kind = 'registry_catalog'
AND registry_id IS NOT NULL AND retention_subscription_id IS NOT NULL
AND refresh_id IS NOT NULL
AND manual_retention_root_id IS NULL
AND retention_lease_id IS NULL AND release_id IS NULL
AND channel_id IS NULL AND partition_bucket IS NULL)
OR(source_kind = 'channel'
AND registry_id IS NOT NULL AND retention_subscription_id IS NOT NULL
AND refresh_id IS NOT NULL
AND manual_retention_root_id IS NULL
AND retention_lease_id IS NULL AND release_id IS NOT NULL
AND channel_id IS NOT NULL AND partition_bucket IS NOT NULL)
OR(source_kind = 'release'
AND registry_id IS NOT NULL AND retention_subscription_id IS NOT NULL
AND refresh_id IS NOT NULL
AND manual_retention_root_id IS NULL
AND retention_lease_id IS NULL AND release_id IS NOT NULL
AND channel_id IS NULL AND partition_bucket IS NULL)),
  UNIQUE(refresh_id, reason_key),
  UNIQUE(manual_retention_root_id, reason_key),
  UNIQUE(id, cache_id),
  UNIQUE(id, cache_id, store_hash),
  FOREIGN KEY(refresh_id, retention_subscription_id, cache_id, registry_id)
  REFERENCES cache_retention_refreshes(refresh_id, subscription_id, cache_id, registry_id),
  FOREIGN KEY(retention_subscription_id, cache_id, registry_id)
  REFERENCES cache_retention_subscriptions(id, cache_id, registry_id),
  FOREIGN KEY(manual_retention_root_id, cache_id)
  REFERENCES manual_retention_roots(id, cache_id),
  FOREIGN KEY(retention_lease_id, manual_retention_root_id)
  REFERENCES retention_leases(id, manual_retention_root_id),
  FOREIGN KEY(release_id, registry_id)
  REFERENCES releases(id, registry_id)
);

CREATE TABLE domain_probe_challenges(
  operation_id KEYTEXT64 NOT NULL,
  target_generation INTEGER NOT NULL,
  attempt INTEGER NOT NULL,
  nonce KEYTEXT64 NOT NULL UNIQUE,
  endpoint_id KEYTEXT64 NOT NULL,
  endpoint_generation INTEGER NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY(operation_id, target_generation, attempt),
  FOREIGN KEY(endpoint_id, endpoint_generation)
    REFERENCES endpoint_revisions(endpoint_id, generation) ON DELETE CASCADE,
  CHECK(target_generation > 0),
  CHECK(attempt >= 0 AND attempt < 3),
  CHECK(expires_at > issued_at)
);

CREATE TABLE endpoint_observations(
  endpoint_id KEYTEXT64 PRIMARY KEY,
  observed_generation INTEGER,
  boundary_id KEYTEXT64 NOT NULL,
  boundary_revision INTEGER,
  state KEYTEXT16 NOT NULL,
  listener_observed INTEGER NOT NULL DEFAULT 0,
  tls_observed INTEGER NOT NULL DEFAULT 0,
  observed_at INTEGER NOT NULL,
  error LONGTEXT,
  FOREIGN KEY(endpoint_id, boundary_id)
  REFERENCES endpoints(id, network_policy_id) ON DELETE CASCADE,
  FOREIGN KEY(endpoint_id, observed_generation, boundary_id, boundary_revision)
  REFERENCES endpoint_revisions(endpoint_id, generation, network_policy_id, boundary_revision),
  CHECK(state IN('unknown', 'declared', 'probing', 'healthy', 'degraded', 'failed')),
  CHECK((observed_generation IS NULL AND boundary_revision IS NULL AND state = 'unknown')
OR(observed_generation IS NOT NULL AND boundary_revision IS NOT NULL)),
  CHECK(state = 'failed' OR error IS NULL)
);

CREATE TABLE endpoint_generation_observations(
  endpoint_id KEYTEXT64 NOT NULL,
  observed_generation INTEGER NOT NULL,
  boundary_id KEYTEXT64 NOT NULL,
  boundary_revision INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  listener_observed INTEGER NOT NULL DEFAULT 0,
  tls_observed INTEGER NOT NULL DEFAULT 0,
  observed_at INTEGER NOT NULL,
  error LONGTEXT,
  PRIMARY KEY(endpoint_id, observed_generation),
  FOREIGN KEY(endpoint_id, observed_generation, boundary_id, boundary_revision)
  REFERENCES endpoint_revisions(endpoint_id, generation, network_policy_id, boundary_revision)
  ON DELETE CASCADE,
  CHECK(state IN('declared', 'probing', 'healthy', 'degraded', 'failed')),
  CHECK(state = 'failed' OR error IS NULL)
);

CREATE TABLE endpoint_route_scopes(
  endpoint_id KEYTEXT64 NOT NULL,
  endpoint_generation INTEGER NOT NULL,
  consumer_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  grant_generation INTEGER NOT NULL,
  grant_kind KEYTEXT32 NOT NULL,
  state KEYTEXT16 NOT NULL,
  granted_by KEYTEXT128 NOT NULL,
  granted_at INTEGER NOT NULL,
  revoked_by KEYTEXT128,
  revoked_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(endpoint_id, endpoint_generation, consumer_scope_key),
  UNIQUE(endpoint_id, endpoint_generation, consumer_scope_key, grant_generation, state),
  FOREIGN KEY(endpoint_id, endpoint_generation)
  REFERENCES endpoint_revisions(endpoint_id, generation) ON DELETE CASCADE,
  CHECK(grant_generation > 0),
  CHECK(grant_kind IN('owner', 'instance_default', 'explicit')),
  CHECK((state = 'active' AND revoked_by IS NULL AND revoked_at IS NULL)
OR(state = 'revoked' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL))
);

CREATE TABLE release_artifact_snapshot_heads(
  release_id INTEGER PRIMARY KEY,
  registry_id INTEGER NOT NULL,
  complete_artifact_snapshot_id KEYTEXT64 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  UNIQUE(release_id, registry_id),
  FOREIGN KEY(release_id, registry_id) REFERENCES releases(id, registry_id),
  FOREIGN KEY(complete_artifact_snapshot_id, release_id, registry_id)
  REFERENCES release_artifact_snapshots(snapshot_id, release_id, registry_id)
);

CREATE TABLE cache_write_tickets(
  ticket_id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL REFERENCES binary_caches(id) ON DELETE CASCADE,
  object_key KEYTEXT512 NOT NULL,
  declared_size INTEGER NOT NULL,
  observed_final_size INTEGER,
  prior_object_size INTEGER,
  prior_object_hash KEYTEXT64,
  prior_object_etag KEYTEXT512,
  intended_object_hash KEYTEXT64,
  uploaded_size INTEGER NOT NULL DEFAULT 0,
  upload_kind KEYTEXT16 NOT NULL,
  placement_id INTEGER NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  placement_write_spec_version INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  write_credential_purpose KEYTEXT16 NOT NULL,
  write_credential_generation INTEGER NOT NULL,
  presign_credential_purpose KEYTEXT16,
  presign_credential_generation INTEGER,
  starting_inventory_generation INTEGER NOT NULL,
  covered_inventory_generation INTEGER,
  backend_upload_id KEYTEXT512,
  direct_upload_acknowledged_at INTEGER,
  direct_upload_observed_etag KEYTEXT512,
  direct_upload_observed_hash KEYTEXT128,
  direct_upload_observed_size INTEGER,
  quota_org_id INTEGER REFERENCES orgs(id) ON DELETE RESTRICT,
  quota_delta_bytes INTEGER NOT NULL DEFAULT 0,
  quota_delta_objects INTEGER NOT NULL DEFAULT 0,
  quota_state KEYTEXT16 NOT NULL DEFAULT 'none',
  state KEYTEXT16 NOT NULL,
  active_cache_slot INTEGER,
  expires_at INTEGER NOT NULL,
  recovery_attempts INTEGER NOT NULL DEFAULT 0,
  recovery_after INTEGER NOT NULL DEFAULT 0,
  recovery_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  backend_create_token KEYTEXT64,
  backend_create_expires_at INTEGER,
  UNIQUE(ticket_id, cache_id),
  UNIQUE(cache_id, object_key, active_cache_slot),
  CHECK(upload_kind IN('single', 'multipart', 'presigned')),
  CHECK(declared_size >= 0 AND uploaded_size >= 0 AND uploaded_size <= declared_size
  AND(observed_final_size IS NULL OR observed_final_size >= 0)
  AND(prior_object_size IS NULL OR prior_object_size >= 0)
  AND(prior_object_hash IS NULL OR length(prior_object_hash) = 64)
  AND(intended_object_hash IS NULL OR length(intended_object_hash) = 64)),
  CHECK((prior_object_size IS NULL AND prior_object_hash IS NULL AND prior_object_etag IS NULL)
    OR(prior_object_size IS NOT NULL AND prior_object_hash IS NOT NULL)),
  CHECK(state IN('observing', 'active', 'completing', 'completed', 'aborted', 'failed')),
  CHECK((state IN('observing', 'active', 'completing') AND active_cache_slot = 1)
OR(state IN('completed', 'aborted', 'failed') AND active_cache_slot IS NULL)),
  CHECK((upload_kind IN('single', 'presigned') AND backend_upload_id IS NULL)
OR upload_kind = 'multipart'),
  CHECK((upload_kind = 'presigned' AND presign_credential_purpose = 'presign'
AND presign_credential_generation IS NOT NULL)
OR(upload_kind <> 'presigned' AND presign_credential_purpose IS NULL
AND presign_credential_generation IS NULL)),
  CHECK((direct_upload_acknowledged_at IS NULL
AND direct_upload_observed_etag IS NULL AND direct_upload_observed_hash IS NULL
AND direct_upload_observed_size IS NULL)
OR(upload_kind = 'presigned' AND direct_upload_acknowledged_at IS NOT NULL
AND direct_upload_observed_size >= 0)),
  CHECK(quota_state IN('none', 'pending', 'reserved', 'committed', 'released')),
  CHECK((quota_org_id IS NULL AND quota_delta_bytes = 0
AND quota_delta_objects = 0 AND quota_state = 'none')
OR(quota_org_id IS NOT NULL AND quota_state <> 'none')),
  CHECK(expires_at > created_at AND resource_version > 0),
  CHECK(recovery_attempts >= 0 AND recovery_after >= 0),
  FOREIGN KEY(placement_id, cache_id) REFERENCES surface_placements(id, cache_id),
  FOREIGN KEY(binding_id, binding_write_revision)
  REFERENCES binding_write_revisions(binding_id, revision),
  FOREIGN KEY(binding_id, write_credential_purpose, write_credential_generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation),
  FOREIGN KEY(binding_id, presign_credential_purpose, presign_credential_generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
);

CREATE TABLE cache_inventory_placement_scans(
  cache_id INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  content_digest KEYTEXT128,
  object_count INTEGER,
  completed_at INTEGER,
  selected_at INTEGER NOT NULL,
  PRIMARY KEY(cache_id, generation, placement_id),
  CHECK(placement_resource_version > 0),
  CHECK(binding_resource_version > 0),
  CHECK((content_digest IS NULL AND object_count IS NULL AND completed_at IS NULL)
OR(content_digest IS NOT NULL AND object_count >= 0 AND completed_at IS NOT NULL)),
  FOREIGN KEY(cache_id, generation)
  REFERENCES cache_inventory_generations(cache_id, generation) ON DELETE CASCADE,
  FOREIGN KEY(placement_id, cache_id)
  REFERENCES surface_placements(id, cache_id)
);

CREATE TABLE cache_inventory_staged_surface_objects(
  cache_id INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  partition_key BLOB NOT NULL,
  content_hash KEYTEXT128 NOT NULL,
  size INTEGER NOT NULL,
  PRIMARY KEY(cache_id, generation, placement_id, object_key),
  FOREIGN KEY(cache_id, generation)
  REFERENCES cache_inventory_generations(cache_id, generation) ON DELETE CASCADE,
  FOREIGN KEY(placement_id, cache_id)
  REFERENCES surface_placements(id, cache_id),
  CHECK(length(partition_key) = 32),
  CHECK(size >= 0)
);

CREATE TABLE cache_inventory_listed_objects(
  cache_id INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  observed_sha256 KEYTEXT64 NOT NULL,
  observed_size INTEGER NOT NULL,
  etag KEYTEXT255,
  PRIMARY KEY(cache_id, generation, placement_id, object_key),
  FOREIGN KEY(cache_id, generation)
  REFERENCES cache_inventory_generations(cache_id, generation) ON DELETE CASCADE,
  FOREIGN KEY(placement_id, cache_id)
  REFERENCES surface_placements(id, cache_id),
  CHECK(length(observed_sha256) = 64),
  CHECK(observed_size >= 0)
);

CREATE TABLE placement_delivery_manifests(
  manifest_id KEYTEXT64 PRIMARY KEY,
  placement_id INTEGER NOT NULL,
  registry_id INTEGER,
  cache_id INTEGER,
  kind KEYTEXT32 NOT NULL,
  registry_publication_id KEYTEXT64,
  cache_inventory_generation INTEGER,
  content_digest KEYTEXT128 NOT NULL,
  published_at INTEGER NOT NULL,
  UNIQUE(manifest_id, placement_id, registry_id),
  UNIQUE(manifest_id, placement_id, cache_id),
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK((kind = 'registry_publication' AND registry_publication_id IS NOT NULL
AND cache_inventory_generation IS NULL)
OR(kind = 'cache_inventory' AND registry_publication_id IS NULL
AND cache_inventory_generation IS NOT NULL)),
  FOREIGN KEY(placement_id, registry_id) REFERENCES surface_placements(id, registry_id),
  FOREIGN KEY(placement_id, cache_id) REFERENCES surface_placements(id, cache_id),
  FOREIGN KEY(registry_publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id),
  FOREIGN KEY(cache_inventory_generation, cache_id)
  REFERENCES cache_inventory_generations(generation, cache_id) ON DELETE CASCADE
);

CREATE TABLE cache_nar_objects(
  cache_id INTEGER NOT NULL REFERENCES binary_caches(id) ON DELETE CASCADE,
  nar_surface_object_id INTEGER NOT NULL,
  nar_hash KEYTEXT128 NOT NULL,
  nar_size INTEGER NOT NULL,
  file_hash KEYTEXT128 NOT NULL,
  file_size INTEGER NOT NULL,
  compression KEYTEXT32 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(cache_id, nar_surface_object_id),
  UNIQUE(cache_id, nar_surface_object_id, nar_hash, nar_size,
file_hash, file_size, compression),
  CHECK(nar_size >= 0 AND file_size >= 0 AND resource_version > 0),
  FOREIGN KEY(nar_surface_object_id, cache_id)
  REFERENCES surface_objects(id, cache_id)
);

CREATE TABLE cache_gc_plan_build_assertions(
  cache_id INTEGER NOT NULL,
  plan_id KEYTEXT64 NOT NULL,
  ok INTEGER NOT NULL,
  asserted_at INTEGER NOT NULL,
  PRIMARY KEY(cache_id, plan_id),
  CHECK(ok = 1),
  FOREIGN KEY(plan_id, cache_id) REFERENCES cache_gc_plans(plan_id, cache_id)
);

CREATE TABLE cache_gc_apply_claims(
  cache_id INTEGER NOT NULL,
  plan_id KEYTEXT64 NOT NULL,
  claim_id KEYTEXT64 NOT NULL,
  expected_epoch INTEGER NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  actor_scope_digest KEYTEXT128 NOT NULL,
  confirmation_hash KEYTEXT128 NOT NULL,
  claimed_at INTEGER NOT NULL,
  PRIMARY KEY(cache_id, plan_id),
  UNIQUE(cache_id, expected_epoch),
  UNIQUE(claim_id, cache_id),
  UNIQUE(claim_id, plan_id, cache_id),
  FOREIGN KEY(plan_id, cache_id) REFERENCES cache_gc_plans(plan_id, cache_id)
);

CREATE TABLE cache_gc_plan_objects(
  cache_id INTEGER NOT NULL,
  plan_id KEYTEXT64 NOT NULL,
  -- Historical evidence: intentionally survives cache-object tombstone reaping.
  cache_object_id INTEGER NOT NULL,
  store_hash KEYTEXT64 NOT NULL,
  expected_object_version INTEGER NOT NULL,
  expected_unreferenced_since INTEGER NOT NULL,
  eligibility_reason KEYTEXT16 NOT NULL,
  logical_bytes INTEGER NOT NULL,
  PRIMARY KEY(cache_id, plan_id, cache_object_id),
  CHECK(expected_object_version > 0 AND logical_bytes >= 0),
  CHECK(eligibility_reason IN('ttl', 'byte_cap', 'object_cap')),
  FOREIGN KEY(plan_id, cache_id) REFERENCES cache_gc_plans(plan_id, cache_id)
);

CREATE TABLE cache_gc_plan_actions(
  action_id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL,
  plan_id KEYTEXT64 NOT NULL,
  surface_object_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  phase KEYTEXT16 NOT NULL,
  expected_etag KEYTEXT255,
  expected_hash KEYTEXT128,
  expected_size INTEGER,
  expected_inventory_generation INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  delete_credential_purpose KEYTEXT16 NOT NULL DEFAULT 'delete',
  delete_credential_generation INTEGER NOT NULL,
  estimated_reclaimable_bytes INTEGER NOT NULL,
  UNIQUE(action_id, plan_id, cache_id),
  UNIQUE(action_id, plan_id, cache_id, surface_object_id, placement_id),
  UNIQUE(cache_id, plan_id, surface_object_id, placement_id),
  UNIQUE(plan_id, surface_object_id, placement_id),
  CHECK(phase IN('narinfo', 'nar')),
  CHECK(expected_size IS NULL OR expected_size >= 0),
  CHECK(expected_inventory_generation > 0),
  CHECK(binding_id > 0 AND binding_resource_version > 0
    AND delete_credential_generation > 0),
  CHECK(delete_credential_purpose = 'delete'),
  CHECK(estimated_reclaimable_bytes >= 0),
  FOREIGN KEY(plan_id, cache_id) REFERENCES cache_gc_plans(plan_id, cache_id),
  FOREIGN KEY(surface_object_id, cache_id) REFERENCES surface_objects(id, cache_id),
  FOREIGN KEY(placement_id, cache_id) REFERENCES surface_placements(id, cache_id),
  FOREIGN KEY(binding_id, delete_credential_purpose, delete_credential_generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
);

CREATE TABLE object_deletion_jobs(
  job_id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL,
  originating_operation_id KEYTEXT64 NOT NULL,
  operation_target_kind KEYTEXT32 NOT NULL DEFAULT('binary_cache'),
  operation_target_stable_id KEYTEXT255 NOT NULL,
  surface_object_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  phase KEYTEXT16 NOT NULL,
  expected_etag KEYTEXT255,
  expected_hash KEYTEXT128,
  expected_size INTEGER,
  expected_inventory_generation INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  delete_credential_purpose KEYTEXT16 NOT NULL DEFAULT 'delete',
  delete_credential_generation INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  active_slot INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL,
  next_attempt_at INTEGER,
  error_class KEYTEXT32,
  error LONGTEXT,
  confirmed_reclaimed_bytes INTEGER NOT NULL DEFAULT 0,
  leaked_bytes INTEGER NOT NULL DEFAULT 0,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER,
  UNIQUE(job_id, cache_id),
  UNIQUE(job_id, cache_id, surface_object_id, placement_id),
  UNIQUE(surface_object_id, placement_id, active_slot),
  CHECK(phase IN('narinfo', 'nar')),
  CHECK(operation_target_kind = 'binary_cache'),
  CHECK(expected_size IS NULL OR expected_size >= 0),
  CHECK(expected_inventory_generation > 0),
  CHECK(binding_id > 0 AND binding_resource_version > 0
    AND delete_credential_generation > 0),
  CHECK(state IN('preparing', 'pending', 'running', 'failed', 'blocked',
'succeeded', 'abandoned', 'cancelled')),
  CHECK(attempt_count >= 0 AND max_attempts > 0
AND attempt_count <= max_attempts),
  CHECK((state IN('preparing', 'pending', 'running', 'failed', 'blocked')
AND active_slot = 1)
OR(state IN('succeeded', 'abandoned', 'cancelled') AND active_slot IS NULL)),
  CHECK(state = 'succeeded' OR confirmed_reclaimed_bytes = 0),
  CHECK(state = 'abandoned' OR leaked_bytes = 0),
  CHECK(confirmed_reclaimed_bytes >= 0 AND leaked_bytes >= 0),
  CHECK(resource_version > 0),
  FOREIGN KEY(originating_operation_id) REFERENCES topology_operations(operation_id),
  FOREIGN KEY(originating_operation_id, operation_target_kind,
    operation_target_stable_id)
  REFERENCES topology_operations(operation_id, primary_target_kind, primary_target_stable_id),
  FOREIGN KEY(cache_id, operation_target_stable_id)
  REFERENCES binary_caches(id, stable_id),
  FOREIGN KEY(surface_object_id, cache_id) REFERENCES surface_objects(id, cache_id),
  FOREIGN KEY(placement_id, cache_id) REFERENCES surface_placements(id, cache_id),
  CHECK(delete_credential_purpose = 'delete'),
  FOREIGN KEY(binding_id, delete_credential_purpose, delete_credential_generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
);

CREATE TABLE cache_gc_first_sweep_acknowledgements(
  acknowledgement_id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL,
  gc_plan_id KEYTEXT64 NOT NULL,
  state KEYTEXT16 NOT NULL,
  expected_cache_epoch INTEGER NOT NULL,
  expected_gc_policy_version INTEGER NOT NULL,
  gc_manifest_digest KEYTEXT128 NOT NULL,
  confirmation_hash KEYTEXT128 NOT NULL,
  created_by KEYTEXT128 NOT NULL,
  acknowledged_by KEYTEXT128,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  acknowledged_at INTEGER,
  UNIQUE(acknowledgement_id, cache_id),
  UNIQUE(acknowledgement_id, cache_id, state),
  CHECK(state IN('planned', 'applied', 'expired')),
  CHECK(expected_cache_epoch >= 0 AND expected_gc_policy_version > 0),
  CHECK(expires_at > created_at),
  CHECK((state = 'planned' AND acknowledged_by IS NULL
AND acknowledged_at IS NULL)
OR(state = 'applied' AND acknowledged_by IS NOT NULL
AND acknowledged_at IS NOT NULL)
OR(state = 'expired' AND acknowledged_by IS NULL
AND acknowledged_at IS NULL)),
  FOREIGN KEY(gc_plan_id, cache_id) REFERENCES cache_gc_plans(plan_id, cache_id)
);

CREATE TABLE registry_publication_manifest_chunks(
  publication_id KEYTEXT64 NOT NULL REFERENCES registry_publication_manifest_sessions(publication_id) ON DELETE CASCADE,
  chunk_index INTEGER NOT NULL,
  chunk_digest KEYTEXT128 NOT NULL,
  object_count INTEGER NOT NULL,
  accepted_at INTEGER NOT NULL,
  PRIMARY KEY(publication_id, chunk_index),
  CHECK(chunk_index >= 0),
  CHECK(object_count > 0)
);

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

CREATE TABLE release_artifacts(
  snapshot_id KEYTEXT64 NOT NULL,
  release_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  package_version KEYTEXT64 NOT NULL,
  platform KEYTEXT64 NOT NULL,
  artifact_kind KEYTEXT32 NOT NULL,
  store_path KEYTEXT512 NOT NULL,
  store_hash KEYTEXT64 NOT NULL,
  metadata_digest KEYTEXT128 NOT NULL,
  CHECK(artifact_kind IN(
    'output', 'image', 'source_derivation', 'expose', 'config',
    'evaluation_base_lib', 'documentation'
  )),
  PRIMARY KEY(snapshot_id, package_name, package_version, platform,
artifact_kind, store_hash),
  FOREIGN KEY(snapshot_id, release_id, registry_id)
  REFERENCES release_artifact_snapshots(snapshot_id, release_id, registry_id)
);

CREATE TABLE release_promotions(
  bundle_digest KEYTEXT128 PRIMARY KEY REFERENCES release_bundles(bundle_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  staging_receipt_digest KEYTEXT128 NOT NULL,
  qualification_digest KEYTEXT128 NOT NULL REFERENCES release_qualifications(qualification_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  production_receipt_digest KEYTEXT128 NOT NULL REFERENCES release_bundle_publications(receipt_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  promoted_at INTEGER NOT NULL,
  UNIQUE(production_receipt_digest)
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

CREATE TABLE oci_blobs(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  digest KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  surface_object_id INTEGER NOT NULL,
  quota_bytes INTEGER NOT NULL,
  lifecycle_state KEYTEXT16 NOT NULL DEFAULT 'active',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  unreferenced_since INTEGER,
  PRIMARY KEY(registry_id, digest),
  UNIQUE(surface_object_id, registry_id),
  FOREIGN KEY(surface_object_id, registry_id)
  REFERENCES surface_objects(id, registry_id) ON DELETE RESTRICT,
  CHECK(byte_size >= 0),
  CHECK(quota_bytes = byte_size),
  CHECK(lifecycle_state IN('active', 'tombstoned', 'deleting'))
);

CREATE TABLE oci_uploads(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL,
  publication_id KEYTEXT64 REFERENCES oci_publications(id) ON DELETE CASCADE,
  expected_digest KEYTEXT128,
  expected_size INTEGER,
  uploaded_size INTEGER NOT NULL DEFAULT 0,
  sha256_state LONGTEXT NOT NULL,
  backend_upload_id KEYTEXT512,
  state KEYTEXT16 NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  CHECK(expected_size IS NULL OR expected_size >= 0),
  CHECK(uploaded_size >= 0),
  CHECK(state IN('active', 'completing', 'complete', 'cancelled', 'failed'))
);

CREATE INDEX oci_uploads_expiry_idx ON oci_uploads(state,
  expires_at);

CREATE TABLE oci_publication_required_placements(
  publication_id KEYTEXT64 NOT NULL
  REFERENCES oci_publication_sessions(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  placement_write_spec_version INTEGER NOT NULL,
  placement_observation_version INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  revision_fingerprint KEYTEXT128 NOT NULL,
  capability_fingerprint KEYTEXT128 NOT NULL,
  PRIMARY KEY(publication_id, placement_id),
  FOREIGN KEY(placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id) ON DELETE RESTRICT,
  CHECK(placement_resource_version >= 1),
  CHECK(placement_write_spec_version >= 1),
  CHECK(placement_observation_version >= 1),
  CHECK(binding_write_revision >= 1)
);

CREATE TABLE oci_publication_objects(
  publication_id KEYTEXT64 NOT NULL REFERENCES oci_publication_sessions(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  object_kind KEYTEXT16 NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  descriptor_json LONGTEXT NOT NULL,
  projection_json LONGTEXT,
  PRIMARY KEY(publication_id, digest),
  CHECK(byte_size >= 0),
  CHECK(object_kind IN('blob', 'manifest'))
);

CREATE TABLE oci_upload_sessions(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL,
  publication_id KEYTEXT64 REFERENCES oci_publication_sessions(id) ON DELETE CASCADE,
  quota_reservation_id KEYTEXT128 NOT NULL
  REFERENCES oci_quota_reservations(id) ON DELETE RESTRICT,
  writer_id KEYTEXT128 NOT NULL,
  token_id KEYTEXT128 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  expected_digest KEYTEXT128,
  expected_size INTEGER,
  maximum_size INTEGER NOT NULL,
  uploaded_size INTEGER NOT NULL DEFAULT 0,
  -- The first accepted PATCH freezes one exact staging placement. Canonical
  -- materialization is frozen separately when finalization is claimed. Each
  -- binding revision is immutable and pins the exact credential generation;
  -- recovery therefore remains possible after placement authority moves.
  staging_placement_id INTEGER,
  staging_placement_resource_version INTEGER,
  staging_binding_id INTEGER,
  staging_binding_write_revision INTEGER,
  final_digest KEYTEXT128,
  materialization_placement_id INTEGER,
  materialization_placement_resource_version INTEGER,
  materialization_binding_id INTEGER,
  materialization_binding_write_revision INTEGER,
  -- Portable SHA-256 continuation state. Words are stored as unsigned values
  -- in non-negative SQL integers; total_bytes includes the pending tail.
  sha256_state_version INTEGER NOT NULL,
  sha256_h0 INTEGER NOT NULL,
  sha256_h1 INTEGER NOT NULL,
  sha256_h2 INTEGER NOT NULL,
  sha256_h3 INTEGER NOT NULL,
  sha256_h4 INTEGER NOT NULL,
  sha256_h5 INTEGER NOT NULL,
  sha256_h6 INTEGER NOT NULL,
  sha256_h7 INTEGER NOT NULL,
  sha256_total_bytes INTEGER NOT NULL,
  sha256_tail_hex KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  cleanup_state KEYTEXT16 NOT NULL DEFAULT 'none',
  cleanup_finished_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, writer_id, idempotency_key),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(staging_placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id) ON DELETE RESTRICT,
  FOREIGN KEY(staging_binding_id, staging_binding_write_revision)
  REFERENCES binding_write_revisions(binding_id, revision) ON DELETE RESTRICT,
  FOREIGN KEY(materialization_placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id) ON DELETE RESTRICT,
  FOREIGN KEY(materialization_binding_id, materialization_binding_write_revision)
  REFERENCES binding_write_revisions(binding_id, revision) ON DELETE RESTRICT,
  CHECK(expected_size IS NULL OR expected_size >= 0),
  CHECK(maximum_size >= 0),
  CHECK(expected_size IS NULL OR expected_size <= maximum_size),
  CHECK(uploaded_size >= 0),
  CHECK(uploaded_size <= maximum_size),
  CHECK((staging_placement_id IS NULL AND staging_placement_resource_version IS NULL
         AND staging_binding_id IS NULL AND staging_binding_write_revision IS NULL)
     OR (staging_placement_id IS NOT NULL AND staging_placement_resource_version >= 1
         AND staging_binding_id IS NOT NULL AND staging_binding_write_revision >= 1)),
  CHECK((materialization_placement_id IS NULL
         AND materialization_placement_resource_version IS NULL
         AND materialization_binding_id IS NULL
         AND materialization_binding_write_revision IS NULL)
     OR (materialization_placement_id IS NOT NULL
         AND materialization_placement_resource_version >= 1
         AND materialization_binding_id IS NOT NULL
         AND materialization_binding_write_revision >= 1)),
  CHECK(sha256_state_version = 1),
  CHECK(sha256_h0 >= 0 AND sha256_h0 <= 4294967295),
  CHECK(sha256_h1 >= 0 AND sha256_h1 <= 4294967295),
  CHECK(sha256_h2 >= 0 AND sha256_h2 <= 4294967295),
  CHECK(sha256_h3 >= 0 AND sha256_h3 <= 4294967295),
  CHECK(sha256_h4 >= 0 AND sha256_h4 <= 4294967295),
  CHECK(sha256_h5 >= 0 AND sha256_h5 <= 4294967295),
  CHECK(sha256_h6 >= 0 AND sha256_h6 <= 4294967295),
  CHECK(sha256_h7 >= 0 AND sha256_h7 <= 4294967295),
  CHECK(sha256_total_bytes >= 0),
  CHECK(length(sha256_tail_hex) <= 126),
  CHECK(state IN('active', 'completing', 'complete', 'cancelled', 'failed')),
  CHECK(cleanup_state IN('none', 'pending', 'complete')),
  CHECK((cleanup_state = 'complete' AND cleanup_finished_at IS NOT NULL)
     OR (cleanup_state <> 'complete' AND cleanup_finished_at IS NULL))
);

CREATE INDEX oci_upload_sessions_expiry_idx ON oci_upload_sessions(state,
  expires_at);

CREATE TABLE oci_conditional_delete_capabilities(
  binding_id INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  delete_credential_purpose KEYTEXT16,
  delete_credential_generation INTEGER,
  capability_fingerprint KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY(binding_id, binding_write_revision),
  FOREIGN KEY(binding_id, binding_write_revision)
  REFERENCES binding_write_revisions(binding_id, revision)
  ON DELETE CASCADE,
  FOREIGN KEY(binding_id, delete_credential_purpose, delete_credential_generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
  ON DELETE RESTRICT,
  CHECK(binding_resource_version >= 1),
  CHECK(state IN('valid', 'invalid')),
  CHECK(resource_version >= 1),
  CHECK((delete_credential_purpose IS NULL
      AND delete_credential_generation IS NULL)
    OR (delete_credential_purpose = 'delete'
      AND delete_credential_generation >= 1))
);

CREATE TABLE oci_provider_inventory_generations(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  placement_id INTEGER NOT NULL,
  collector_id KEYTEXT128 NOT NULL,
  collector_claim_token KEYTEXT64 NOT NULL,
  collector_lease_expires_at INTEGER,
  idempotency_key KEYTEXT128 NOT NULL,
  source_kind KEYTEXT32 NOT NULL,
  captured_mutation_epoch INTEGER NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  placement_write_spec_version INTEGER NOT NULL,
  placement_observation_version INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  active_slot INTEGER,
  inventory_digest KEYTEXT128,
  object_count INTEGER NOT NULL DEFAULT 0,
  byte_count INTEGER NOT NULL DEFAULT 0,
  untracked_object_count INTEGER NOT NULL DEFAULT 0,
  checkpoint_ordinal INTEGER NOT NULL DEFAULT 0,
  provider_cursor KEYTEXT512,
  checkpoint_last_key KEYTEXT512,
  checkpoint_digest KEYTEXT128,
  checkpoint_page_digest KEYTEXT128,
  takeover_count INTEGER NOT NULL DEFAULT 0,
  started_at INTEGER NOT NULL,
  observed_at INTEGER,
  completed_at INTEGER,
  last_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  purge_fence_resource_version INTEGER,
  UNIQUE(registry_id, placement_id, collector_id, idempotency_key),
  UNIQUE(placement_id, active_slot),
  UNIQUE(id, registry_id, placement_id),
  FOREIGN KEY(placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(binding_id, binding_write_revision)
  REFERENCES binding_write_revisions(binding_id, revision) ON DELETE RESTRICT,
  CHECK(source_kind = 'provider_enumeration_v1'),
  CHECK(captured_mutation_epoch >= 0),
  CHECK(placement_resource_version >= 1),
  CHECK(placement_write_spec_version >= 1),
  CHECK(placement_observation_version >= 1),
  CHECK(binding_resource_version >= 1),
  CHECK(state IN('collecting', 'sealing', 'complete', 'failed')),
  CHECK((state IN('collecting', 'sealing') AND active_slot = 1
      AND collector_lease_expires_at IS NOT NULL)
    OR (state IN('complete', 'failed') AND active_slot IS NULL
      AND collector_lease_expires_at IS NULL)),
  CHECK(object_count >= 0 AND byte_count >= 0),
  CHECK(checkpoint_ordinal >= 0),
  CHECK(takeover_count >= 0),
  CHECK((checkpoint_ordinal = 0 AND checkpoint_last_key IS NULL
      AND checkpoint_digest IS NULL AND checkpoint_page_digest IS NULL)
    OR (checkpoint_ordinal > 0 AND checkpoint_digest IS NOT NULL
      AND checkpoint_page_digest IS NOT NULL)),
  CHECK(untracked_object_count >= 0 AND untracked_object_count <= object_count),
  CHECK(resource_version >= 1),
  CHECK((state IN('collecting', 'sealing') AND inventory_digest IS NULL
      AND observed_at IS NULL AND completed_at IS NULL)
    OR (state = 'complete' AND inventory_digest IS NOT NULL
      AND observed_at IS NOT NULL AND completed_at IS NOT NULL)
    OR (state = 'failed' AND completed_at IS NOT NULL))
);

CREATE TABLE oci_gc_candidate_repositories(
  run_id KEYTEXT64 NOT NULL,
  digest KEYTEXT128 NOT NULL,
  repository_id INTEGER NOT NULL,
  repository_name KEYTEXT255 NOT NULL,
  PRIMARY KEY(run_id, digest, repository_id),
  FOREIGN KEY(run_id, digest)
  REFERENCES oci_gc_candidates(run_id, digest) ON DELETE CASCADE
);

CREATE TABLE oci_gc_placement_actions(
  id KEYTEXT64 PRIMARY KEY,
  run_id KEYTEXT64 NOT NULL,
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  placement_id INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  expected_hash KEYTEXT128 NOT NULL,
  expected_size INTEGER NOT NULL,
  expected_strong_etag KEYTEXT512,
  inventory_generation_id KEYTEXT64 NOT NULL,
  inventory_entry_present INTEGER NOT NULL,
  state KEYTEXT32 NOT NULL,
  worker_id KEYTEXT128,
  claim_token KEYTEXT64,
  lease_expires_at INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 8,
  next_attempt_at INTEGER NOT NULL,
  requeue_actor_id KEYTEXT128,
  requeue_idempotency_key KEYTEXT128,
  requeue_expected_resource_version INTEGER,
  last_error LONGTEXT,
  confirmed_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(run_id, digest, placement_id),
  UNIQUE(requeue_actor_id, requeue_idempotency_key),
  FOREIGN KEY(run_id, digest)
  REFERENCES oci_gc_candidates(run_id, digest) ON DELETE CASCADE,
  FOREIGN KEY(run_id, placement_id)
  REFERENCES oci_gc_placement_snapshots(run_id, placement_id) ON DELETE CASCADE,
  CHECK(expected_size >= 0),
  CHECK(inventory_entry_present IN(0, 1)),
  CHECK((inventory_entry_present = 1 AND expected_strong_etag IS NOT NULL)
    OR (inventory_entry_present = 0 AND expected_strong_etag IS NULL)),
  CHECK(state IN('pending', 'claimed', 'confirmed_absent', 'failed')),
  CHECK(attempt_count >= 0 AND max_attempts > 0),
  CHECK(resource_version >= 1),
  CHECK((requeue_actor_id IS NULL AND requeue_idempotency_key IS NULL
      AND requeue_expected_resource_version IS NULL)
    OR (requeue_actor_id IS NOT NULL AND requeue_idempotency_key IS NOT NULL
      AND requeue_expected_resource_version >= 1)),
  CHECK((state = 'claimed' AND worker_id IS NOT NULL AND claim_token IS NOT NULL
      AND lease_expires_at IS NOT NULL)
    OR (state <> 'claimed' AND worker_id IS NULL AND claim_token IS NULL
      AND lease_expires_at IS NULL)),
  CHECK((state = 'confirmed_absent' AND confirmed_at IS NOT NULL)
    OR (state <> 'confirmed_absent' AND confirmed_at IS NULL))
);

CREATE TABLE release_browse_tree_entries(
  registry_id INTEGER NOT NULL,
  source_commit KEYTEXT64 NOT NULL,
  entry_key KEYTEXT64 NOT NULL,
  node_key KEYTEXT64,
  document_sha256 KEYTEXT128 NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  package_version KEYTEXT64 NOT NULL,
  platform KEYTEXT64 NOT NULL,
  kind KEYTEXT32 NOT NULL,
  document_key TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  type_signature TEXT,
  PRIMARY KEY(registry_id, source_commit, entry_key),
  FOREIGN KEY(registry_id, source_commit)
    REFERENCES release_browse_catalogs(registry_id, source_commit) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, source_commit, node_key)
    REFERENCES release_browse_tree_nodes(registry_id, source_commit, node_key) ON DELETE CASCADE
);

CREATE TABLE surface_write_authorities(
  id INTEGER PRIMARY KEY,
  incarnation_id KEYTEXT64 NOT NULL UNIQUE,
  registry_id INTEGER REFERENCES registries(id) ON DELETE RESTRICT,
  cache_id INTEGER REFERENCES binary_caches(id) ON DELETE RESTRICT,
  mode KEYTEXT32 NOT NULL DEFAULT 'single_writer',
  desired_placement_id INTEGER NOT NULL,
  desired_write_spec_version INTEGER NOT NULL,
  desired_binding_write_revision INTEGER NOT NULL,
  desired_generation INTEGER NOT NULL,
  observed_placement_id INTEGER,
  observed_write_spec_version INTEGER,
  observed_binding_write_revision INTEGER,
  observed_generation INTEGER,
  reconciliation_state KEYTEXT32 NOT NULL DEFAULT 'pending',
  reconciliation_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK(mode = 'single_writer'),
  CHECK(desired_generation > 0),
  CHECK(desired_write_spec_version > 0),
  CHECK(desired_binding_write_revision > 0),
  CHECK(observed_generation IS NULL OR observed_generation >= 0),
  CHECK(observed_generation IS NULL OR observed_generation <= desired_generation),
  CHECK(reconciliation_state IN('pending', 'ready', 'failed')),
  CHECK((observed_placement_id IS NULL
AND observed_write_spec_version IS NULL
AND observed_binding_write_revision IS NULL
AND observed_generation IS NULL)
OR(observed_placement_id IS NOT NULL
AND observed_write_spec_version IS NOT NULL
AND observed_binding_write_revision IS NOT NULL
AND observed_generation IS NOT NULL)),
  CHECK(reconciliation_state <> 'ready'
OR(observed_placement_id = desired_placement_id
AND observed_write_spec_version = desired_write_spec_version
AND observed_binding_write_revision = desired_binding_write_revision
AND observed_generation = desired_generation)),
  CHECK(reconciliation_state = 'ready'
OR observed_generation IS NULL
OR desired_generation > observed_generation),
  CHECK((reconciliation_state = 'failed' AND reconciliation_error IS NOT NULL)
OR(reconciliation_state <> 'failed' AND reconciliation_error IS NULL)),
  UNIQUE(registry_id),
  UNIQUE(cache_id),
  FOREIGN KEY(desired_placement_id, registry_id, desired_write_spec_version)
  REFERENCES surface_placements(id, registry_id, write_spec_version)
  ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(desired_placement_id, cache_id, desired_write_spec_version)
  REFERENCES surface_placements(id, cache_id, write_spec_version)
  ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(desired_placement_id, desired_write_spec_version,
desired_binding_write_revision)
  REFERENCES surface_placement_write_capabilities(placement_id, placement_write_spec_version, binding_write_revision)
  ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(observed_placement_id, registry_id, observed_write_spec_version)
  REFERENCES surface_placements(id, registry_id, write_spec_version)
  ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(observed_placement_id, cache_id, observed_write_spec_version)
  REFERENCES surface_placements(id, cache_id, write_spec_version)
  ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(observed_placement_id, observed_write_spec_version,
observed_binding_write_revision)
  REFERENCES surface_placement_write_capabilities(placement_id, placement_write_spec_version, binding_write_revision)
  ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE placement_policy_complete_members(
  policy_revision_id KEYTEXT64 NOT NULL,
  group_id KEYTEXT64 NOT NULL,
  registry_id INTEGER,
  cache_id INTEGER,
  policy_kind KEYTEXT32 NOT NULL,
  group_purpose KEYTEXT32 NOT NULL,
  placement_id INTEGER NOT NULL,
  placement_kind KEYTEXT16 NOT NULL,
  member_order INTEGER NOT NULL,
  PRIMARY KEY(policy_revision_id, group_id, placement_id),
  UNIQUE(policy_revision_id, group_id, member_order),
  UNIQUE(policy_revision_id, placement_id),
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK(member_order >= 0),
  CHECK(placement_kind = 'complete'),
  CHECK((policy_kind = 'ordered_failover' AND group_purpose = 'ordered')
OR(policy_kind = 'local_then_remote' AND group_purpose IN('local', 'remote'))
OR(policy_kind = 'hash_partition' AND group_purpose = 'complete_fallback')),
  FOREIGN KEY(policy_revision_id, group_id, registry_id, policy_kind, group_purpose)
  REFERENCES placement_policy_replica_groups(
    policy_revision_id, group_id, registry_id, policy_kind, purpose),
  FOREIGN KEY(policy_revision_id, group_id, cache_id, policy_kind, group_purpose)
  REFERENCES placement_policy_replica_groups(
    policy_revision_id, group_id, cache_id, policy_kind, purpose),
  FOREIGN KEY(placement_id, registry_id, placement_kind)
  REFERENCES surface_placements(id, registry_id, kind),
  FOREIGN KEY(placement_id, cache_id, placement_kind)
  REFERENCES surface_placements(id, cache_id, kind)
);

CREATE TABLE placement_policy_shard_members(
  policy_revision_id KEYTEXT64 NOT NULL,
  group_id KEYTEXT64 NOT NULL,
  registry_id INTEGER,
  cache_id INTEGER,
  policy_kind KEYTEXT32 NOT NULL,
  group_purpose KEYTEXT32 NOT NULL,
  range_start INTEGER NOT NULL,
  range_end INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  placement_kind KEYTEXT16 NOT NULL,
  member_order INTEGER NOT NULL,
  PRIMARY KEY(policy_revision_id, group_id, placement_id),
  UNIQUE(policy_revision_id, group_id, member_order),
  UNIQUE(policy_revision_id, placement_id),
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK(member_order >= 0),
  CHECK(policy_kind = 'hash_partition'),
  CHECK(group_purpose = 'hash_range'),
  CHECK(placement_kind = 'shard'),
  FOREIGN KEY(policy_revision_id, group_id, registry_id, policy_kind,
group_purpose, range_start, range_end)
  REFERENCES placement_policy_replica_groups(policy_revision_id, group_id,
registry_id, policy_kind, purpose, range_start, range_end),
  FOREIGN KEY(policy_revision_id, group_id, cache_id, policy_kind,
group_purpose, range_start, range_end)
  REFERENCES placement_policy_replica_groups(policy_revision_id, group_id,
cache_id, policy_kind, purpose, range_start, range_end),
  FOREIGN KEY(placement_id, registry_id, placement_kind, range_start, range_end)
  REFERENCES surface_placements(id, registry_id, kind, hash_range_start, hash_range_end),
  FOREIGN KEY(placement_id, cache_id, placement_kind, range_start, range_end)
  REFERENCES surface_placements(id, cache_id, kind, hash_range_start, hash_range_end)
);

CREATE TABLE registry_publication_multipart_uploads(
  upload_id KEYTEXT64 PRIMARY KEY,
  publication_id KEYTEXT64 NOT NULL,
  registry_id INTEGER NOT NULL,
  surface_object_id INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  active_object_slot INTEGER,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  hashed_size INTEGER NOT NULL DEFAULT 0,
  sha256_state LONGTEXT NOT NULL
    DEFAULT '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19',
  pending_part INTEGER,
  pending_hash LONGTEXT,
  pending_token KEYTEXT64,
  pending_since INTEGER,
  completion_token KEYTEXT64,
  completion_since INTEGER,
  UNIQUE(publication_id, surface_object_id, active_object_slot),
  CHECK(state IN('active', 'completing', 'completed', 'aborted', 'failed')),
  CHECK((state IN('active', 'completing') AND active_object_slot = 1
AND finished_at IS NULL)
OR(state IN('completed', 'aborted', 'failed') AND active_object_slot IS NULL
AND finished_at IS NOT NULL)),
  CHECK(expires_at > created_at),
  FOREIGN KEY(publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id),
  FOREIGN KEY(publication_id, surface_object_id)
  REFERENCES registry_publication_objects(publication_id, surface_object_id)
);

CREATE TABLE gateway_revisions(
  gateway_id KEYTEXT64 NOT NULL,
  generation INTEGER NOT NULL,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  owner_scope_key KEYTEXT64 NOT NULL,
  path_reservation_id KEYTEXT64 NOT NULL,
  binding_id INTEGER NOT NULL,
  endpoint_id KEYTEXT64 NOT NULL,
  endpoint_generation INTEGER NOT NULL,
  endpoint_ingress_kind KEYTEXT16 NOT NULL,
  client_base_path KEYTEXT512 NOT NULL,
  origin_prefix KEYTEXT512 NOT NULL,
  access_policy_kind KEYTEXT32 NOT NULL,
  access_boundary_id KEYTEXT64,
  access_boundary_revision INTEGER,
  external_provider_kind KEYTEXT64,
  external_provider_resource_id KEYTEXT128,
  external_provider_revision KEYTEXT128,
  access_policy_json LONGTEXT NOT NULL,
  access_policy_digest KEYTEXT128 NOT NULL,
  content_digest KEYTEXT128 NOT NULL,
  created_by KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(gateway_id, generation),
  UNIQUE(gateway_id, generation, endpoint_id, endpoint_generation,
binding_id, client_base_path, access_policy_digest),
  UNIQUE(gateway_id, generation, owner_scope_key),
  FOREIGN KEY(gateway_id, owner_scope_key) REFERENCES gateways(id, owner_scope_key),
  FOREIGN KEY(binding_id, owner_scope_key)
  REFERENCES binding_consumer_scopes(binding_id, consumer_scope_key),
  FOREIGN KEY(endpoint_id, endpoint_generation, endpoint_ingress_kind)
  REFERENCES endpoint_revisions(endpoint_id, generation, ingress_kind),
  FOREIGN KEY(endpoint_id, endpoint_generation, owner_scope_key)
  REFERENCES endpoint_route_scopes(endpoint_id, endpoint_generation, consumer_scope_key),
  FOREIGN KEY(access_boundary_id, access_boundary_revision)
  REFERENCES network_policy_revisions(boundary_id, revision),
  FOREIGN KEY(access_boundary_id, owner_scope_key)
  REFERENCES network_policy_consumer_scopes(boundary_id, consumer_scope_key),
  FOREIGN KEY(path_reservation_id, gateway_id, endpoint_id, client_base_path)
  REFERENCES gateway_path_reservations(reservation_id, gateway_id, endpoint_id, client_base_path),
  CHECK(generation > 0),
  CHECK(endpoint_ingress_kind IN('external', 'layer7')),
  CHECK(access_policy_kind IN('public', 'external_provider', 'private_network')),
  CHECK((access_policy_kind = 'public' AND access_boundary_id IS NULL
AND access_boundary_revision IS NULL AND external_provider_kind IS NULL
AND external_provider_resource_id IS NULL AND external_provider_revision IS NULL)
OR(access_policy_kind = 'external_provider' AND access_boundary_id IS NULL
AND access_boundary_revision IS NULL AND external_provider_kind IS NOT NULL
AND external_provider_resource_id IS NOT NULL AND external_provider_revision IS NOT NULL)
OR(access_policy_kind = 'private_network' AND access_boundary_id IS NOT NULL
AND access_boundary_revision IS NOT NULL AND external_provider_kind IS NULL
AND external_provider_resource_id IS NULL AND external_provider_revision IS NULL))
);

CREATE TABLE cache_root_release_provenance(
  root_reason_id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  release_id INTEGER NOT NULL,
  release_snapshot_id KEYTEXT64 NOT NULL,
  UNIQUE(root_reason_id, cache_id),
  FOREIGN KEY(root_reason_id, cache_id)
  REFERENCES cache_root_reasons(id, cache_id),
  FOREIGN KEY(release_snapshot_id, release_id, registry_id)
  REFERENCES release_artifact_snapshots(snapshot_id, release_id, registry_id)
);

CREATE TABLE cache_write_ticket_parts(
  ticket_id KEYTEXT64 NOT NULL REFERENCES cache_write_tickets(ticket_id) ON DELETE CASCADE,
  part_number INTEGER NOT NULL,
  admitted_size INTEGER NOT NULL,
  body_digest KEYTEXT64 NOT NULL,
  state KEYTEXT16 NOT NULL,
  etag KEYTEXT512,
  PRIMARY KEY(ticket_id, part_number),
  CHECK(part_number BETWEEN 1 AND 10000
    AND admitted_size > 0 AND length(body_digest) = 64),
  CHECK(state IN('admitted', 'ambiguous', 'confirmed')),
  CHECK((state = 'confirmed' AND etag IS NOT NULL)
    OR(state IN('admitted', 'ambiguous') AND etag IS NULL))
);

CREATE TABLE cache_inventory_object_observations(
  cache_id INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  placement_id INTEGER NOT NULL,
  state KEYTEXT32 NOT NULL,
  observed_hash KEYTEXT128,
  observed_size INTEGER,
  etag KEYTEXT255,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY(cache_id, generation, placement_id, object_key),
  CHECK(state IN('present', 'copying', 'missing', 'corrupt', 'deleting')),
  CHECK(observed_size IS NULL OR observed_size >= 0),
  FOREIGN KEY(cache_id, generation)
  REFERENCES cache_inventory_generations(cache_id, generation) ON DELETE CASCADE,
  FOREIGN KEY(cache_id, generation, placement_id, object_key)
  REFERENCES cache_inventory_staged_surface_objects(cache_id, generation, placement_id, object_key)
  ON DELETE CASCADE,
  FOREIGN KEY(placement_id, cache_id)
  REFERENCES surface_placements(id, cache_id)
);

CREATE TABLE cache_inventory_narinfo_candidates(
  cache_id INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  store_hash KEYTEXT64 NOT NULL,
  placement_id INTEGER NOT NULL,
  identity_digest KEYTEXT128 NOT NULL,
  narinfo_object_key KEYTEXT512 NOT NULL,
  nar_object_key KEYTEXT512 NOT NULL,
  store_name KEYTEXT255 NOT NULL,
  nar_hash KEYTEXT128 NOT NULL,
  nar_size INTEGER NOT NULL,
  file_hash KEYTEXT128 NOT NULL,
  file_size INTEGER NOT NULL,
  compression KEYTEXT32 NOT NULL,
  deriver KEYTEXT512,
  signature LONGTEXT,
  content_address LONGTEXT,
  published_at INTEGER NOT NULL,
  PRIMARY KEY(cache_id, generation, store_hash, placement_id),
  FOREIGN KEY(cache_id, generation)
  REFERENCES cache_inventory_generations(cache_id, generation) ON DELETE CASCADE,
  FOREIGN KEY(placement_id, cache_id)
  REFERENCES surface_placements(id, cache_id),
  FOREIGN KEY(cache_id, generation, placement_id, narinfo_object_key)
  REFERENCES cache_inventory_staged_surface_objects(cache_id, generation, placement_id, object_key),
  FOREIGN KEY(cache_id, generation, placement_id, nar_object_key)
  REFERENCES cache_inventory_staged_surface_objects(cache_id, generation, placement_id, object_key),
  CHECK(nar_size >= 0 AND file_size >= 0),
  CHECK(narinfo_object_key <> nar_object_key)
);

CREATE TABLE placement_delivery_manifest_heads(
  placement_id INTEGER PRIMARY KEY,
  registry_id INTEGER,
  cache_id INTEGER,
  manifest_id KEYTEXT64 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  FOREIGN KEY(manifest_id, placement_id, registry_id)
  REFERENCES placement_delivery_manifests(manifest_id, placement_id, registry_id),
  FOREIGN KEY(manifest_id, placement_id, cache_id)
  REFERENCES placement_delivery_manifests(manifest_id, placement_id, cache_id)
);

CREATE TABLE endpoint_scope_grant_pins(
  pin_id KEYTEXT64 PRIMARY KEY,
  endpoint_id KEYTEXT64 NOT NULL,
  endpoint_generation INTEGER NOT NULL,
  consumer_scope_key KEYTEXT64 NOT NULL,
  grant_generation INTEGER NOT NULL,
  grant_state KEYTEXT16 NOT NULL DEFAULT 'active',
  target_kind KEYTEXT32 NOT NULL,
  target_stable_id KEYTEXT64 NOT NULL,
  target_generation_key INTEGER NOT NULL,
  target_configuration_digest KEYTEXT128 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(endpoint_id, endpoint_generation, consumer_scope_key, target_kind,
target_stable_id, target_generation_key, target_configuration_digest),
  FOREIGN KEY(endpoint_id, endpoint_generation, consumer_scope_key, grant_generation, grant_state)
  REFERENCES endpoint_route_scopes(endpoint_id, endpoint_generation, consumer_scope_key, grant_generation, state),
  CHECK(grant_state = 'active')
);

CREATE TABLE cache_objects(
  id INTEGER PRIMARY KEY,
  cache_id INTEGER NOT NULL REFERENCES binary_caches(id) ON DELETE CASCADE,
  store_hash KEYTEXT64 NOT NULL,
  store_name KEYTEXT255 NOT NULL,
  narinfo_surface_object_id INTEGER NOT NULL,
  nar_surface_object_id INTEGER NOT NULL,
  nar_hash KEYTEXT128 NOT NULL,
  nar_size INTEGER NOT NULL,
  file_hash KEYTEXT128 NOT NULL,
  file_size INTEGER NOT NULL,
  compression KEYTEXT32 NOT NULL,
  deriver KEYTEXT512,
  signature LONGTEXT,
  content_address LONGTEXT,
  reference_count INTEGER NOT NULL,
  lifecycle_state KEYTEXT16 NOT NULL DEFAULT 'active',
  published_at INTEGER NOT NULL,
  last_access_observed_at INTEGER,
  last_access_source KEYTEXT32,
  unreferenced_since INTEGER,
  tombstoned_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(id, cache_id),
  UNIQUE(id, cache_id, store_hash),
  UNIQUE(cache_id, store_hash),
  UNIQUE(cache_id, narinfo_surface_object_id),
  CHECK(nar_size >= 0 AND file_size >= 0),
  CHECK(reference_count >= 0),
  CHECK(narinfo_surface_object_id <> nar_surface_object_id),
  CHECK(lifecycle_state IN('active', 'tombstoned')),
  CHECK((lifecycle_state = 'active' AND tombstoned_at IS NULL)
OR(lifecycle_state = 'tombstoned' AND tombstoned_at IS NOT NULL)),
  CHECK(resource_version > 0),
  FOREIGN KEY(narinfo_surface_object_id, cache_id)
  REFERENCES surface_objects(id, cache_id),
  FOREIGN KEY(nar_surface_object_id, cache_id)
  REFERENCES surface_objects(id, cache_id),
  FOREIGN KEY(cache_id, nar_surface_object_id, nar_hash, nar_size,
file_hash, file_size, compression)
  REFERENCES cache_nar_objects(cache_id, nar_surface_object_id, nar_hash,
nar_size, file_hash, file_size, compression)
);

CREATE TABLE cache_gc_generation_roots(
  cache_id INTEGER NOT NULL,
  generation_id KEYTEXT64 NOT NULL,
  root_reason_id KEYTEXT64 NOT NULL,
  store_hash KEYTEXT64 NOT NULL,
  PRIMARY KEY(cache_id, generation_id, root_reason_id),
  FOREIGN KEY(generation_id, cache_id)
  REFERENCES cache_gc_generations(generation_id, cache_id),
  FOREIGN KEY(root_reason_id, cache_id, store_hash)
  REFERENCES cache_root_reasons(id, cache_id, store_hash)
);

CREATE TABLE cache_gc_apply_assertions(
  cache_id INTEGER NOT NULL,
  plan_id KEYTEXT64 NOT NULL,
  claim_id KEYTEXT64 NOT NULL,
  ok INTEGER NOT NULL,
  asserted_at INTEGER NOT NULL,
  PRIMARY KEY(cache_id, plan_id),
  CHECK(ok = 1),
  FOREIGN KEY(claim_id, plan_id, cache_id)
  REFERENCES cache_gc_apply_claims(claim_id, plan_id, cache_id)
);

CREATE TABLE cache_gc_plan_object_actions(
  cache_id INTEGER NOT NULL,
  plan_id KEYTEXT64 NOT NULL,
  cache_object_id INTEGER NOT NULL,
  action_id KEYTEXT64 NOT NULL,
  PRIMARY KEY(cache_id, plan_id, cache_object_id, action_id),
  FOREIGN KEY(cache_id, plan_id, cache_object_id)
  REFERENCES cache_gc_plan_objects(cache_id, plan_id, cache_object_id),
  FOREIGN KEY(action_id, plan_id, cache_id)
  REFERENCES cache_gc_plan_actions(action_id, plan_id, cache_id)
);

CREATE TABLE cache_gc_action_dependencies(
  cache_id INTEGER NOT NULL,
  plan_id KEYTEXT64 NOT NULL,
  action_id KEYTEXT64 NOT NULL,
  prerequisite_action_id KEYTEXT64 NOT NULL,
  PRIMARY KEY(cache_id, plan_id, action_id, prerequisite_action_id),
  CHECK(action_id <> prerequisite_action_id),
  FOREIGN KEY(action_id, plan_id, cache_id)
  REFERENCES cache_gc_plan_actions(action_id, plan_id, cache_id),
  FOREIGN KEY(prerequisite_action_id, plan_id, cache_id)
  REFERENCES cache_gc_plan_actions(action_id, plan_id, cache_id)
);

CREATE TABLE cache_gc_retry_requests(
  cache_id INTEGER NOT NULL,
  job_id KEYTEXT64 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  expected_resource_version INTEGER NOT NULL,
  resulting_resource_version INTEGER NOT NULL,
  requested_at INTEGER NOT NULL,
  PRIMARY KEY(cache_id, job_id, idempotency_key),
  CHECK(expected_resource_version > 0),
  CHECK(resulting_resource_version = expected_resource_version + 1),
  FOREIGN KEY(job_id, cache_id)
  REFERENCES object_deletion_jobs(job_id, cache_id)
);

CREATE TABLE object_deletion_attempt_receipts(
  request_id KEYTEXT64 PRIMARY KEY,
  cache_id INTEGER NOT NULL,
  job_id KEYTEXT64 NOT NULL,
  attempt_number INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  surface_object_id INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  expected_etag KEYTEXT255,
  expected_hash KEYTEXT128,
  expected_size INTEGER,
  expected_inventory_generation INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  delete_credential_purpose KEYTEXT16 NOT NULL DEFAULT 'delete',
  delete_credential_generation INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  outcome KEYTEXT32,
  response_etag KEYTEXT255,
  response_hash KEYTEXT128,
  response_size INTEGER,
  error_class KEYTEXT32,
  response_detail LONGTEXT,
  requested_at INTEGER NOT NULL,
  responded_at INTEGER,
  finalized_at INTEGER,
  UNIQUE(cache_id, job_id, attempt_number),
  CHECK(attempt_number > 0),
  CHECK(expected_size IS NULL OR expected_size >= 0),
  CHECK(response_size IS NULL OR response_size >= 0),
  CHECK(expected_inventory_generation > 0),
  CHECK(binding_id > 0 AND binding_resource_version > 0
    AND delete_credential_generation > 0),
  CHECK(delete_credential_purpose = 'delete'),
  CHECK(state IN('requested', 'responded', 'finalized')),
  CHECK(outcome IS NULL OR outcome IN(
    'deleted', 'not_found', 'precondition_failed', 'backend_error')),
  CHECK((state = 'requested' AND outcome IS NULL
    AND responded_at IS NULL AND finalized_at IS NULL)
  OR(state = 'responded' AND outcome IS NOT NULL
    AND responded_at IS NOT NULL AND finalized_at IS NULL)
  OR(state = 'finalized' AND outcome IS NOT NULL
    AND responded_at IS NOT NULL AND finalized_at IS NOT NULL)),
  CHECK((outcome IN('deleted', 'not_found')
    AND error_class IS NULL AND response_detail IS NULL)
  OR(outcome IN('precondition_failed', 'backend_error')
    AND error_class IS NOT NULL AND response_detail IS NOT NULL)
  OR(outcome IS NULL)),
  FOREIGN KEY(job_id, cache_id)
  REFERENCES object_deletion_jobs(job_id, cache_id),
  FOREIGN KEY(surface_object_id, cache_id)
  REFERENCES surface_objects(id, cache_id),
  FOREIGN KEY(placement_id, cache_id)
  REFERENCES surface_placements(id, cache_id),
  FOREIGN KEY(binding_id, delete_credential_purpose, delete_credential_generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
);

CREATE TABLE cache_gc_action_jobs(
  cache_id INTEGER NOT NULL,
  plan_id KEYTEXT64 NOT NULL,
  action_id KEYTEXT64 NOT NULL,
  job_id KEYTEXT64 NOT NULL,
  surface_object_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  PRIMARY KEY(cache_id, plan_id, action_id),
  FOREIGN KEY(action_id, plan_id, cache_id, surface_object_id, placement_id)
  REFERENCES cache_gc_plan_actions(
action_id, plan_id, cache_id, surface_object_id, placement_id),
  FOREIGN KEY(job_id, cache_id, surface_object_id, placement_id)
  REFERENCES object_deletion_jobs(job_id, cache_id, surface_object_id, placement_id)
);

CREATE TABLE cache_gc_operation_jobs(
  operation_id KEYTEXT64 NOT NULL,
  cache_id INTEGER NOT NULL,
  operation_target_kind KEYTEXT32 NOT NULL DEFAULT('binary_cache'),
  operation_target_stable_id KEYTEXT255 NOT NULL,
  plan_id KEYTEXT64 NOT NULL,
  job_id KEYTEXT64 NOT NULL,
  PRIMARY KEY(operation_id, cache_id, job_id),
  UNIQUE(cache_id, plan_id, job_id),
  CHECK(operation_target_kind = 'binary_cache'),
  FOREIGN KEY(operation_id) REFERENCES topology_operations(operation_id),
  FOREIGN KEY(operation_id, operation_target_kind, operation_target_stable_id)
  REFERENCES topology_operations(operation_id, primary_target_kind, primary_target_stable_id),
  FOREIGN KEY(cache_id, operation_target_stable_id)
  REFERENCES binary_caches(id, stable_id),
  FOREIGN KEY(plan_id, cache_id) REFERENCES cache_gc_plans(plan_id, cache_id),
  FOREIGN KEY(job_id, cache_id)
  REFERENCES object_deletion_jobs(job_id, cache_id)
);

CREATE TABLE cache_gc_heads(
  cache_id INTEGER PRIMARY KEY REFERENCES cache_gc_state(cache_id) ON DELETE CASCADE,
  current_mark_generation_id KEYTEXT64,
  first_sweep_acknowledgement_id KEYTEXT64,
  first_sweep_acknowledgement_state KEYTEXT16,
  first_sweep_acknowledged_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  CHECK((first_sweep_acknowledgement_id IS NULL
AND first_sweep_acknowledgement_state IS NULL
AND first_sweep_acknowledged_at IS NULL)
OR(first_sweep_acknowledgement_id IS NOT NULL
AND first_sweep_acknowledgement_state = 'applied'
AND first_sweep_acknowledged_at IS NOT NULL)),
  FOREIGN KEY(current_mark_generation_id, cache_id)
  REFERENCES cache_gc_generations(generation_id, cache_id),
  FOREIGN KEY(first_sweep_acknowledgement_id, cache_id,
first_sweep_acknowledgement_state)
  REFERENCES cache_gc_first_sweep_acknowledgements(
acknowledgement_id, cache_id, state)
);

CREATE TABLE registry_publication_object_evidence(
  publication_id KEYTEXT64 NOT NULL,
  surface_object_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  observed_hash KEYTEXT128 NOT NULL,
  observed_size INTEGER NOT NULL,
  strong_etag KEYTEXT255,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY(publication_id, surface_object_id, placement_id),
  FOREIGN KEY(publication_id, surface_object_id)
  REFERENCES registry_publication_objects(publication_id, surface_object_id)
  ON DELETE CASCADE,
  FOREIGN KEY(publication_id, placement_id)
  REFERENCES registry_publication_placements(publication_id, placement_id)
  ON DELETE CASCADE,
  CHECK(observed_size >= 0)
);

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

CREATE TABLE release_package_documentation(
  snapshot_id KEYTEXT64 NOT NULL,
  release_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  package_version KEYTEXT64 NOT NULL,
  platform KEYTEXT64 NOT NULL,
  artifact_kind KEYTEXT32 NOT NULL DEFAULT 'documentation',
  store_path KEYTEXT512 NOT NULL,
  store_hash KEYTEXT64 NOT NULL,
  format KEYTEXT64 NOT NULL,
  nar_hash KEYTEXT128 NOT NULL,
  nar_size INTEGER NOT NULL,
  document_sha256 KEYTEXT128 NOT NULL,
  document_size INTEGER NOT NULL,
  semantic_schema_sha256 KEYTEXT128 NOT NULL,
  system_module_nar_hash KEYTEXT128,
  metadata_digest KEYTEXT128 NOT NULL,
  PRIMARY KEY(snapshot_id, package_name, package_version, platform),
  CHECK(artifact_kind = 'documentation'),
  CHECK(format = 'aos.package-documentation/v1+json'),
  CHECK(nar_size > 0 AND nar_size <= 4194304),
  CHECK(document_size > 0 AND document_size <= 4194304),
  FOREIGN KEY(snapshot_id, release_id, registry_id)
    REFERENCES release_artifact_snapshots(snapshot_id, release_id, registry_id)
    ON DELETE CASCADE,
  FOREIGN KEY(snapshot_id, package_name, package_version, platform,
              artifact_kind, store_hash)
    REFERENCES release_artifacts(snapshot_id, package_name, package_version,
                                 platform, artifact_kind, store_hash)
    ON DELETE CASCADE
);

CREATE TABLE oci_repository_objects(
  repository_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  object_kind KEYTEXT16 NOT NULL,
  linked_at INTEGER NOT NULL,
  media_type KEYTEXT128 NOT NULL DEFAULT 'application/octet-stream',
  PRIMARY KEY(repository_id, digest),
  UNIQUE(registry_id, repository_id, digest),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE RESTRICT,
  CHECK(object_kind IN('blob', 'manifest'))
);

CREATE TABLE oci_manifests(
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  schema_version INTEGER NOT NULL,
  artifact_type KEYTEXT128,
  subject_digest KEYTEXT128,
  config_digest KEYTEXT128,
  platform_os KEYTEXT32,
  platform_architecture KEYTEXT32,
  platform_variant KEYTEXT32,
  annotations_json LONGTEXT NOT NULL DEFAULT ('{}'),
  descriptor_count INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  platform_os_version KEYTEXT512,
  platform_os_features_json LONGTEXT NOT NULL DEFAULT ('[]'),
  PRIMARY KEY(registry_id, digest),
  FOREIGN KEY(registry_id, digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, subject_digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE RESTRICT,
  FOREIGN KEY(registry_id, config_digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE RESTRICT,
  CHECK(byte_size >= 0),
  CHECK(schema_version = 2),
  CHECK(descriptor_count >= 0 AND descriptor_count <= 1024)
);

CREATE TABLE oci_leases(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  lease_kind KEYTEXT16 NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(registry_id, digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE CASCADE,
  CHECK(lease_kind IN('pull', 'upload', 'publication', 'operator'))
);

CREATE TABLE oci_publication_object_placements(
  publication_id KEYTEXT64 NOT NULL,
  digest KEYTEXT128 NOT NULL,
  registry_id INTEGER NOT NULL,
  surface_object_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  object_resource_version INTEGER NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  placement_observation_version INTEGER NOT NULL,
  observed_inventory_generation INTEGER NOT NULL,
  observed_size INTEGER NOT NULL,
  observed_etag KEYTEXT512 NOT NULL,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY(publication_id, digest, placement_id),
  FOREIGN KEY(publication_id, digest)
  REFERENCES oci_publication_objects(publication_id, digest) ON DELETE CASCADE,
  CHECK(observed_size >= 0),
  CHECK(object_resource_version >= 1),
  CHECK(placement_resource_version >= 1),
  CHECK(placement_observation_version >= 1),
  CHECK(observed_inventory_generation >= 0)
);

CREATE TABLE oci_upload_chunks(
  upload_id KEYTEXT64 NOT NULL REFERENCES oci_upload_sessions(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  byte_offset INTEGER NOT NULL,
  byte_size INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  staging_object_key KEYTEXT512 NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(upload_id, ordinal),
  UNIQUE(upload_id, byte_offset),
  UNIQUE(staging_object_key),
  CHECK(ordinal >= 0),
  CHECK(byte_offset >= 0),
  CHECK(byte_size > 0)
);

CREATE TABLE oci_blob_claims(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  digest KEYTEXT128 NOT NULL,
  upload_id KEYTEXT64 NOT NULL UNIQUE REFERENCES oci_upload_sessions(id) ON DELETE CASCADE,
  claimed_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, digest)
);

CREATE TABLE oci_provider_inventory_entries(
  generation_id KEYTEXT64 NOT NULL
  REFERENCES oci_provider_inventory_generations(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  object_digest KEYTEXT128 NOT NULL,
  observed_hash KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  strong_etag KEYTEXT512 NOT NULL,
  surface_object_id INTEGER,
  catalog_object_resource_version INTEGER,
  classification KEYTEXT16 NOT NULL,
  deleted_at INTEGER,
  PRIMARY KEY(generation_id, object_key),
  FOREIGN KEY(generation_id, registry_id, placement_id)
  REFERENCES oci_provider_inventory_generations(id, registry_id, placement_id)
  ON DELETE CASCADE,
  CHECK(byte_size >= 0),
  CHECK(length(strong_etag) > 0),
  CHECK(classification IN('tracked', 'untracked')),
  CHECK((classification = 'tracked' AND surface_object_id IS NOT NULL
      AND catalog_object_resource_version >= 1)
    OR (classification = 'untracked' AND surface_object_id IS NULL
      AND catalog_object_resource_version IS NULL))
);

CREATE TABLE oci_provider_inventory_heads(
  placement_id INTEGER PRIMARY KEY,
  registry_id INTEGER NOT NULL,
  generation_id KEYTEXT64 NOT NULL UNIQUE,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(generation_id, registry_id, placement_id)
  REFERENCES oci_provider_inventory_generations(id, registry_id, placement_id)
  ON DELETE CASCADE,
  FOREIGN KEY(placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id) ON DELETE CASCADE
);

CREATE TABLE oci_gc_deletion_evidence(
  action_id KEYTEXT64 PRIMARY KEY
  REFERENCES oci_gc_placement_actions(id) ON DELETE CASCADE,
  response_idempotency_key KEYTEXT128 NOT NULL UNIQUE,
  outcome KEYTEXT32 NOT NULL,
  conditional_etag KEYTEXT512,
  provider_request_id KEYTEXT255,
  evidence_digest KEYTEXT128 NOT NULL,
  confirmed_at INTEGER NOT NULL,
  CHECK(outcome IN('deleted', 'already_absent')),
  CHECK(outcome <> 'deleted' OR conditional_etag IS NOT NULL)
);

CREATE TABLE oci_untracked_repair_plans(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  placement_id INTEGER NOT NULL,
  placement_name KEYTEXT128 NOT NULL,
  placement_prefix KEYTEXT512 NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  placement_write_spec_version INTEGER NOT NULL,
  placement_observation_version INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  delete_credential_purpose KEYTEXT16,
  delete_credential_generation INTEGER,
  delete_capability_fingerprint KEYTEXT128 NOT NULL,
  delete_capability_resource_version INTEGER NOT NULL,
  inventory_generation_id KEYTEXT64 NOT NULL,
  inventory_digest KEYTEXT128 NOT NULL,
  inventory_observed_at INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  object_digest KEYTEXT128 NOT NULL,
  observed_hash KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  strong_etag KEYTEXT512 NOT NULL,
  repair_kind KEYTEXT16 NOT NULL,
  adopt_media_type KEYTEXT128,
  actor_id KEYTEXT128 NOT NULL,
  plan_idempotency_key KEYTEXT128 NOT NULL,
  apply_idempotency_key KEYTEXT128,
  captured_mutation_epoch INTEGER NOT NULL,
  confirmation_hash KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  worker_id KEYTEXT128,
  claim_token KEYTEXT64,
  lease_expires_at INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 8,
  next_attempt_at INTEGER NOT NULL,
  response_idempotency_key KEYTEXT128,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  applied_at INTEGER,
  finished_at INTEGER,
  last_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, actor_id, plan_idempotency_key),
  UNIQUE(id, registry_id),
  FOREIGN KEY(inventory_generation_id, registry_id, placement_id)
  REFERENCES oci_provider_inventory_generations(id, registry_id, placement_id)
  ON DELETE RESTRICT,
  CHECK(byte_size >= 0),
  CHECK(placement_resource_version >= 1),
  CHECK(placement_write_spec_version >= 1),
  CHECK(placement_observation_version >= 1),
  CHECK(binding_resource_version >= 1),
  CHECK(binding_write_revision >= 1),
  CHECK(delete_capability_resource_version >= 1),
  CHECK((delete_credential_purpose IS NULL AND delete_credential_generation IS NULL)
    OR (delete_credential_purpose = 'delete' AND delete_credential_generation >= 1)),
  CHECK(repair_kind IN('delete', 'adopt')),
  CHECK((repair_kind = 'delete' AND adopt_media_type IS NULL)
    OR (repair_kind = 'adopt' AND adopt_media_type IS NOT NULL)),
  CHECK(captured_mutation_epoch >= 0),
  CHECK(state IN('planned', 'pending', 'claimed', 'confirmed_absent',
                 'adopted', 'failed', 'aborted')),
  CHECK(expires_at > created_at),
  CHECK(attempt_count >= 0 AND max_attempts >= 1),
  CHECK((state = 'claimed' AND worker_id IS NOT NULL AND claim_token IS NOT NULL
      AND lease_expires_at IS NOT NULL)
    OR (state <> 'claimed' AND worker_id IS NULL AND claim_token IS NULL
      AND lease_expires_at IS NULL)),
  CHECK(resource_version >= 1)
);

CREATE TABLE release_browse_search_terms(
  registry_id INTEGER NOT NULL,
  source_commit KEYTEXT64 NOT NULL,
  term KEYTEXT512 NOT NULL,
  entry_key KEYTEXT64 NOT NULL,
  weight INTEGER NOT NULL,
  PRIMARY KEY(registry_id, source_commit, term, entry_key),
  FOREIGN KEY(registry_id, source_commit, entry_key)
    REFERENCES release_browse_tree_entries(registry_id, source_commit, entry_key) ON DELETE CASCADE
);

CREATE TABLE registry_publication_multipart_parts(
  upload_id KEYTEXT64 NOT NULL
    REFERENCES registry_publication_multipart_uploads(upload_id),
  part_number INTEGER NOT NULL,
  placement_id INTEGER NOT NULL REFERENCES surface_placements(id),
  etag LONGTEXT NOT NULL,
  PRIMARY KEY(upload_id, part_number, placement_id),
  CHECK(part_number > 0),
  CHECK(length(etag) BETWEEN 1 AND 1024)
);

CREATE TABLE registry_publication_multipart_backends(
  upload_id KEYTEXT64 NOT NULL
    REFERENCES registry_publication_multipart_uploads(upload_id),
  placement_id INTEGER NOT NULL REFERENCES surface_placements(id),
  placement_resource_version INTEGER NOT NULL,
  backend_upload_id KEYTEXT1024,
  state KEYTEXT16 NOT NULL,
  completion_etag LONGTEXT,
  PRIMARY KEY(upload_id, placement_id),
  CHECK(state IN('creating', 'ready', 'uncertain')),
  CHECK((state = 'creating' AND backend_upload_id IS NULL)
    OR(state IN('ready', 'uncertain') AND backend_upload_id IS NOT NULL))
);

CREATE TABLE gateway_revision_route_scopes(
  gateway_id KEYTEXT64 NOT NULL,
  generation INTEGER NOT NULL,
  consumer_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE CASCADE,
  grant_generation INTEGER NOT NULL,
  grant_kind KEYTEXT32 NOT NULL,
  state KEYTEXT16 NOT NULL,
  granted_by KEYTEXT128 NOT NULL,
  granted_at INTEGER NOT NULL,
  revoked_by KEYTEXT128,
  revoked_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(gateway_id, generation, consumer_scope_key),
  UNIQUE(gateway_id, generation, consumer_scope_key, grant_generation, state),
  FOREIGN KEY(gateway_id, generation)
  REFERENCES gateway_revisions(gateway_id, generation) ON DELETE CASCADE,
  CHECK(grant_generation > 0),
  CHECK(grant_kind IN('owner', 'instance_default', 'explicit')),
  CHECK((state = 'active' AND revoked_by IS NULL AND revoked_at IS NULL)
OR(state = 'revoked' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL))
);

CREATE TABLE cache_inventory_candidate_references(
  cache_id INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  store_hash KEYTEXT64 NOT NULL,
  placement_id INTEGER NOT NULL,
  referenced_store_hash KEYTEXT64 NOT NULL,
  PRIMARY KEY(cache_id, generation, store_hash, placement_id, referenced_store_hash),
  FOREIGN KEY(cache_id, generation, store_hash, placement_id)
  REFERENCES cache_inventory_narinfo_candidates(cache_id, generation, store_hash, placement_id)
  ON DELETE CASCADE
);

CREATE TABLE cache_object_references(
  cache_id INTEGER NOT NULL,
  cache_object_id INTEGER NOT NULL,
  referenced_store_hash KEYTEXT64 NOT NULL,
  referenced_cache_object_id INTEGER,
  PRIMARY KEY(cache_id, cache_object_id, referenced_store_hash),
  FOREIGN KEY(cache_object_id, cache_id)
  REFERENCES cache_objects(id, cache_id),
  FOREIGN KEY(referenced_cache_object_id, cache_id, referenced_store_hash)
  REFERENCES cache_objects(id, cache_id, store_hash)
);

CREATE TABLE gateway_revision_events(
  event_id KEYTEXT64 PRIMARY KEY,
  gateway_id KEYTEXT64 NOT NULL,
  generation INTEGER NOT NULL,
  gateway_resource_version INTEGER NOT NULL,
  transition KEYTEXT16 NOT NULL,
  actor_id KEYTEXT128 NOT NULL,
  occurred_at INTEGER NOT NULL,
  UNIQUE(gateway_id, generation),
  FOREIGN KEY(gateway_id, generation)
  REFERENCES gateway_revisions(gateway_id, generation),
  CHECK(transition = 'desired')
);

CREATE TABLE oci_descriptor_edges(
  registry_id INTEGER NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  edge_role KEYTEXT16 NOT NULL,
  ordinal INTEGER NOT NULL,
  target_digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  platform_os KEYTEXT32,
  platform_architecture KEYTEXT32,
  platform_variant KEYTEXT32,
  annotations_json LONGTEXT NOT NULL DEFAULT ('{}'),
  platform_os_version KEYTEXT512,
  platform_os_features_json LONGTEXT NOT NULL DEFAULT ('[]'),
  PRIMARY KEY(registry_id, manifest_digest, edge_role, ordinal),
  FOREIGN KEY(registry_id, manifest_digest)
  REFERENCES oci_manifests(registry_id, digest) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, target_digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE RESTRICT,
  CHECK(edge_role IN('config', 'layer', 'child', 'subject', 'payload')),
  CHECK(ordinal >= 0),
  CHECK(byte_size >= 0)
);

CREATE TABLE oci_tags(
  repository_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  name KEYTEXT128 NOT NULL,
  digest KEYTEXT128 NOT NULL,
  source_kind KEYTEXT16 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(repository_id, name),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT,
  CHECK(source_kind IN('manual', 'release', 'channel'))
);

CREATE TABLE oci_release_roots(
  registry_id INTEGER NOT NULL,
  release_id INTEGER NOT NULL,
  release_tag KEYTEXT255 NOT NULL,
  repository_id INTEGER NOT NULL,
  container_name KEYTEXT128 NOT NULL,
  index_digest KEYTEXT128 NOT NULL,
  source_commit KEYTEXT128 NOT NULL,
  verified_tag_oid KEYTEXT128 NOT NULL,
  catalog_digest KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  publication_fence INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(registry_id, release_tag, repository_id, container_name),
  FOREIGN KEY(release_id, registry_id)
  REFERENCES releases(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, index_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT
);

CREATE TABLE oci_image_config_projections(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  config_digest KEYTEXT128 NOT NULL,
  operating_system KEYTEXT32 NOT NULL,
  architecture KEYTEXT32 NOT NULL,
  variant KEYTEXT32,
  os_version KEYTEXT512,
  os_features_json LONGTEXT NOT NULL DEFAULT ('[]'),
  aos_system KEYTEXT64 NOT NULL,
  compressed_byte_size INTEGER NOT NULL,
  unpacked_byte_size INTEGER NOT NULL,
  layer_count INTEGER NOT NULL,
  config_json LONGTEXT NOT NULL,
  verified_at INTEGER NOT NULL,
  PRIMARY KEY(repository_id, root_digest, manifest_digest),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, manifest_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, config_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT,
  CHECK(compressed_byte_size >= 0),
  CHECK(unpacked_byte_size >= 0),
  CHECK(layer_count >= 0 AND layer_count <= 64),
  CHECK(length(config_json) <= 4194304),
  CHECK(length(os_features_json) <= 4096)
);

CREATE TABLE oci_release_layers(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  ordinal INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  compressed_byte_size INTEGER NOT NULL,
  unpacked_byte_size INTEGER NOT NULL,
  diff_id KEYTEXT128 NOT NULL,
  closure_group KEYTEXT128 NOT NULL DEFAULT (''),
  verified_at INTEGER NOT NULL,
  PRIMARY KEY(repository_id, root_digest, manifest_digest, ordinal),
  UNIQUE(repository_id, root_digest, manifest_digest, digest),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT,
  CHECK(ordinal >= 0 AND ordinal < 64),
  CHECK(compressed_byte_size >= 0),
  CHECK(unpacked_byte_size >= 0)
);

CREATE TABLE oci_admin_projection_reconciliations(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  config_digest KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL DEFAULT ('pending'),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error LONGTEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, repository_id, root_digest, manifest_digest),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, manifest_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, config_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT,
  CHECK(state IN('pending', 'failed')),
  CHECK(attempts >= 0)
);

CREATE TABLE oci_release_provenance(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  release_tag KEYTEXT255 NOT NULL,
  channel_name KEYTEXT128,
  signed_release_root KEYTEXT128 NOT NULL,
  catalog_digest KEYTEXT128 NOT NULL,
  verification KEYTEXT16 NOT NULL,
  verified_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, repository_id, root_digest, release_tag),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, root_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT,
  CHECK(verification IN('verified', 'invalid'))
);

CREATE TABLE oci_untracked_repair_credential_holds(
  plan_id KEYTEXT64 NOT NULL
  REFERENCES oci_untracked_repair_plans(id) ON DELETE CASCADE,
  binding_id INTEGER NOT NULL,
  purpose KEYTEXT16 NOT NULL,
  generation INTEGER NOT NULL,
  PRIMARY KEY(plan_id, binding_id, purpose, generation),
  FOREIGN KEY(binding_id, purpose, generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
  ON DELETE RESTRICT,
  CHECK(purpose = 'delete'),
  CHECK(generation >= 1)
);

CREATE TABLE oci_untracked_repair_evidence(
  plan_id KEYTEXT64 PRIMARY KEY
  REFERENCES oci_untracked_repair_plans(id) ON DELETE CASCADE,
  outcome KEYTEXT32 NOT NULL,
  provider_request_id KEYTEXT255,
  conditional_etag KEYTEXT512,
  evidence_digest KEYTEXT128 NOT NULL,
  confirmed_at INTEGER NOT NULL,
  CHECK(outcome IN('deleted', 'already_absent', 'adopted')),
  CHECK((outcome = 'deleted' AND conditional_etag IS NOT NULL)
    OR outcome IN('already_absent', 'adopted'))
);

CREATE TABLE routes(
  id KEYTEXT64 PRIMARY KEY,
  url_reservation_id KEYTEXT64 NOT NULL REFERENCES route_url_reservations(id),
  resource_version INTEGER NOT NULL DEFAULT 1,
  endpoint_id KEYTEXT64 NOT NULL,
  endpoint_generation INTEGER NOT NULL,
  endpoint_ingress_kind KEYTEXT16 NOT NULL,
  consumer_scope_key KEYTEXT64 NOT NULL,
  gateway_id KEYTEXT64,
  gateway_generation INTEGER,
  target_binding_id INTEGER,
  gateway_client_base_path KEYTEXT512,
  target_placement_prefix KEYTEXT512,
  base_path KEYTEXT512 NOT NULL,
  registry_id INTEGER REFERENCES registries(id) ON DELETE CASCADE,
  cache_id INTEGER REFERENCES binary_caches(id) ON DELETE CASCADE,
  mode KEYTEXT16 NOT NULL,
  access_policy_kind KEYTEXT32 NOT NULL,
  access_boundary_id KEYTEXT64,
  access_boundary_revision INTEGER,
  external_provider_kind KEYTEXT64,
  external_provider_resource_id KEYTEXT128,
  external_provider_revision KEYTEXT128,
  access_policy_json LONGTEXT NOT NULL,
  access_policy_digest KEYTEXT128 NOT NULL,
  placement_id INTEGER,
  target_placement_kind KEYTEXT16,
  placement_policy_revision_id KEYTEXT64,
  placement_policy_revision_state KEYTEXT16,
  serves_git INTEGER NOT NULL DEFAULT 0,
  serves_cache INTEGER NOT NULL DEFAULT 0,
  serves_web INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK(mode IN('hub_proxy', 'hub_redirect', 'direct')),
  CHECK(access_policy_kind IN('public', 'hub_auth', 'external_provider', 'private_network')),
  CHECK((access_policy_kind IN('public', 'hub_auth')
AND access_boundary_id IS NULL AND access_boundary_revision IS NULL
AND external_provider_kind IS NULL AND external_provider_resource_id IS NULL
AND external_provider_revision IS NULL)
OR(access_policy_kind = 'external_provider'
AND access_boundary_id IS NULL AND access_boundary_revision IS NULL
AND external_provider_kind IS NOT NULL AND external_provider_resource_id IS NOT NULL
AND external_provider_revision IS NOT NULL)
OR(access_policy_kind = 'private_network'
AND access_boundary_id IS NOT NULL AND access_boundary_revision IS NOT NULL
AND external_provider_kind IS NULL AND external_provider_resource_id IS NULL
AND external_provider_revision IS NULL)),
  CHECK((mode = 'direct' AND endpoint_ingress_kind IN('external', 'layer7')
AND placement_id IS NOT NULL AND target_placement_kind = 'complete'
AND placement_policy_revision_id IS NULL
AND placement_policy_revision_state IS NULL
AND gateway_id IS NOT NULL AND gateway_generation IS NOT NULL
AND target_binding_id IS NOT NULL
AND gateway_client_base_path IS NOT NULL AND target_placement_prefix IS NOT NULL)
OR(mode IN('hub_proxy', 'hub_redirect') AND endpoint_ingress_kind IN('hub', 'layer7')
AND ((placement_id IS NOT NULL AND target_placement_kind = 'complete'
AND placement_policy_revision_id IS NULL
AND placement_policy_revision_state IS NULL)
OR(placement_id IS NULL AND target_placement_kind IS NULL
AND placement_policy_revision_id IS NOT NULL
AND placement_policy_revision_state = 'published'))
AND gateway_id IS NULL AND gateway_generation IS NULL
AND target_binding_id IS NULL AND gateway_client_base_path IS NULL
AND target_placement_prefix IS NULL)),
  CHECK(serves_git = 1 OR serves_cache = 1 OR serves_web = 1),
  CHECK(enabled IN(0, 1)),
  UNIQUE(endpoint_id, base_path),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id),
  UNIQUE(id, access_policy_digest),
  UNIQUE(id, registry_id, endpoint_id, endpoint_generation, placement_id,
gateway_id, gateway_generation),
  UNIQUE(id, cache_id, endpoint_id, endpoint_generation, placement_id,
gateway_id, gateway_generation),
  FOREIGN KEY(endpoint_id, endpoint_generation, consumer_scope_key)
  REFERENCES endpoint_route_scopes(endpoint_id, endpoint_generation, consumer_scope_key),
  FOREIGN KEY(endpoint_id, endpoint_generation, endpoint_ingress_kind)
  REFERENCES endpoint_revisions(endpoint_id, generation, ingress_kind),
  FOREIGN KEY(registry_id, consumer_scope_key) REFERENCES registries(id, owner_scope_key),
  FOREIGN KEY(cache_id, consumer_scope_key) REFERENCES binary_caches(id, owner_scope_key),
  FOREIGN KEY(placement_id, registry_id) REFERENCES surface_placements(id, registry_id),
  FOREIGN KEY(placement_id, cache_id) REFERENCES surface_placements(id, cache_id),
  FOREIGN KEY(placement_id, target_placement_kind)
  REFERENCES surface_placements(id, kind),
  FOREIGN KEY(placement_policy_revision_id, registry_id,
placement_policy_revision_state)
  REFERENCES placement_policy_revisions(id, registry_id, state),
  FOREIGN KEY(placement_policy_revision_id, cache_id,
placement_policy_revision_state)
  REFERENCES placement_policy_revisions(id, cache_id, state),
  FOREIGN KEY(access_boundary_id, access_boundary_revision)
  REFERENCES network_policy_revisions(boundary_id, revision),
  FOREIGN KEY(access_boundary_id, consumer_scope_key)
  REFERENCES network_policy_consumer_scopes(boundary_id, consumer_scope_key),
  FOREIGN KEY(placement_id, target_binding_id, target_placement_prefix)
  REFERENCES surface_placements(id, binding_id, prefix),
  FOREIGN KEY(gateway_id, gateway_generation, consumer_scope_key)
  REFERENCES gateway_revision_route_scopes(gateway_id, generation, consumer_scope_key),
  FOREIGN KEY(gateway_id, gateway_generation, endpoint_id,
endpoint_generation, target_binding_id,
gateway_client_base_path, access_policy_digest)
  REFERENCES gateway_revisions(gateway_id, generation, endpoint_id,
endpoint_generation, binding_id, client_base_path,
access_policy_digest)
);

CREATE INDEX routes_registry_idx ON routes(registry_id,
  id);

CREATE INDEX routes_cache_idx ON routes(cache_id,
  id);

CREATE TABLE gateway_scope_grant_pins(
  pin_id KEYTEXT64 PRIMARY KEY,
  gateway_id KEYTEXT64 NOT NULL,
  generation INTEGER NOT NULL,
  consumer_scope_key KEYTEXT64 NOT NULL,
  grant_generation INTEGER NOT NULL,
  grant_state KEYTEXT16 NOT NULL DEFAULT 'active',
  target_kind KEYTEXT32 NOT NULL,
  target_stable_id KEYTEXT64 NOT NULL,
  target_generation_key INTEGER NOT NULL,
  target_configuration_digest KEYTEXT128 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(gateway_id, generation, consumer_scope_key, target_kind,
target_stable_id, target_generation_key, target_configuration_digest),
  FOREIGN KEY(gateway_id, generation, consumer_scope_key, grant_generation, grant_state)
  REFERENCES gateway_revision_route_scopes(gateway_id, generation, consumer_scope_key, grant_generation, state),
  CHECK(grant_state = 'active')
);

CREATE TABLE topology_defaults(
  id INTEGER PRIMARY KEY,
  scope_kind KEYTEXT16 NOT NULL,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  scope_key KEYTEXT64 NOT NULL UNIQUE,
  binding_id INTEGER,
  domain_id INTEGER,
  endpoint_id KEYTEXT64,
  endpoint_generation INTEGER,
  gateway_id KEYTEXT64,
  gateway_generation INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK((scope_kind = 'instance' AND org_id IS NULL AND scope_key = 'instance')
OR(scope_kind = 'organization' AND org_id IS NOT NULL)),
  CHECK((endpoint_id IS NULL AND endpoint_generation IS NULL)
OR(endpoint_id IS NOT NULL AND endpoint_generation IS NOT NULL)),
  CHECK((gateway_id IS NULL AND gateway_generation IS NULL)
OR(gateway_id IS NOT NULL AND gateway_generation IS NOT NULL)),
  FOREIGN KEY(binding_id, scope_key)
  REFERENCES binding_consumer_scopes(binding_id, consumer_scope_key),
  FOREIGN KEY(domain_id, scope_key) REFERENCES domains(id, owner_scope_key),
  FOREIGN KEY(endpoint_id, endpoint_generation, scope_key)
  REFERENCES endpoint_route_scopes(endpoint_id, endpoint_generation, consumer_scope_key),
  FOREIGN KEY(gateway_id, gateway_generation, scope_key)
  REFERENCES gateway_revision_route_scopes(gateway_id, generation, consumer_scope_key)
);

CREATE UNIQUE INDEX topology_defaults_org_idx ON topology_defaults(org_id);

CREATE TABLE oci_release_closure_members(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  release_tag KEYTEXT255 NOT NULL,
  store_path KEYTEXT512 NOT NULL,
  nar_hash KEYTEXT128 NOT NULL,
  nar_size INTEGER NOT NULL,
  layer_digest KEYTEXT128 NOT NULL,
  is_direct INTEGER NOT NULL,
  PRIMARY KEY(registry_id, repository_id, root_digest, release_tag, store_path),
  FOREIGN KEY(registry_id, repository_id, root_digest, release_tag)
  REFERENCES oci_release_provenance(
    registry_id, repository_id, root_digest, release_tag
  )
  ON DELETE CASCADE,
  CHECK(nar_size >= 0),
  CHECK(is_direct IN(0, 1))
);

CREATE TABLE oci_release_evidence(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  release_tag KEYTEXT255 NOT NULL,
  evidence_kind KEYTEXT32 NOT NULL,
  digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  verification KEYTEXT16 NOT NULL,
  referrer_digest KEYTEXT128 NOT NULL,
  PRIMARY KEY(registry_id, repository_id, root_digest, release_tag, evidence_kind),
  FOREIGN KEY(registry_id, repository_id, root_digest, release_tag)
  REFERENCES oci_release_provenance(
    registry_id, repository_id, root_digest, release_tag
  )
  ON DELETE CASCADE,
  CHECK(verification IN('verified', 'invalid'))
);

CREATE TABLE route_configurations(
  route_id KEYTEXT64 NOT NULL,
  registry_id INTEGER,
  cache_id INTEGER,
  configuration_generation INTEGER NOT NULL,
  configuration_digest KEYTEXT128 NOT NULL,
  canonical_rendered_url LONGTEXT NOT NULL,
  canonical_configuration_json LONGTEXT NOT NULL,
  created_by KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(route_id, configuration_generation),
  UNIQUE(route_id, registry_id, configuration_generation, configuration_digest),
  UNIQUE(route_id, cache_id, configuration_generation, configuration_digest),
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  FOREIGN KEY(route_id, registry_id) REFERENCES routes(id, registry_id),
  FOREIGN KEY(route_id, cache_id) REFERENCES routes(id, cache_id)
);

CREATE TABLE route_advertisements(
  id INTEGER PRIMARY KEY,
  registry_id INTEGER REFERENCES registries(id) ON DELETE CASCADE,
  cache_id INTEGER REFERENCES binary_caches(id) ON DELETE CASCADE,
  audience KEYTEXT16 NOT NULL,
  route_id KEYTEXT64 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  CHECK(audience IN('git', 'nix_cache', 'web')),
  UNIQUE(registry_id, audience),
  UNIQUE(cache_id, audience),
  FOREIGN KEY(route_id, registry_id) REFERENCES routes(id, registry_id),
  FOREIGN KEY(route_id, cache_id) REFERENCES routes(id, cache_id)
);

CREATE TABLE route_heads(
  route_id KEYTEXT64 PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE,
  registry_id INTEGER,
  cache_id INTEGER,
  configuration_generation INTEGER NOT NULL,
  configuration_digest KEYTEXT128 NOT NULL,
  access_policy_digest KEYTEXT128 NOT NULL,
  CHECK((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
+(CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
  UNIQUE(route_id, registry_id, configuration_generation, configuration_digest),
  UNIQUE(route_id, cache_id, configuration_generation, configuration_digest),
  UNIQUE(route_id, configuration_generation, configuration_digest,
access_policy_digest),
  FOREIGN KEY(route_id, registry_id, configuration_generation,
configuration_digest)
  REFERENCES route_configurations(route_id, registry_id,
configuration_generation, configuration_digest),
  FOREIGN KEY(route_id, cache_id, configuration_generation,
configuration_digest)
  REFERENCES route_configurations(route_id, cache_id,
configuration_generation, configuration_digest),
  FOREIGN KEY(route_id, access_policy_digest)
  REFERENCES routes(id, access_policy_digest)
);

CREATE TABLE registry_cache_stack_entries(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  stack_path KEYTEXT512 NOT NULL,
  committed_url LONGTEXT NOT NULL,
  resolved_priority INTEGER NOT NULL,
  mirror_group_id KEYTEXT128,
  cache_id INTEGER REFERENCES binary_caches(id),
  route_id KEYTEXT64,
  route_configuration_generation INTEGER,
  route_configuration_digest KEYTEXT128,
  indexed_commit KEYTEXT128 NOT NULL,
  PRIMARY KEY(registry_id, stack_path),
  CHECK((cache_id IS NULL AND route_id IS NULL
AND route_configuration_generation IS NULL
AND route_configuration_digest IS NULL)
OR(cache_id IS NOT NULL AND route_id IS NOT NULL
AND route_configuration_generation IS NOT NULL
AND route_configuration_digest IS NOT NULL)),
  FOREIGN KEY(route_id, cache_id, route_configuration_generation,
route_configuration_digest)
  REFERENCES route_configurations(route_id, cache_id,
configuration_generation, configuration_digest)
);

CREATE TABLE consumer_cache_publication_intents(
  change_id KEYTEXT64 NOT NULL REFERENCES change_requests(change_id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  committed_url LONGTEXT NOT NULL,
  cache_id INTEGER REFERENCES binary_caches(id),
  route_id KEYTEXT64,
  route_configuration_generation INTEGER,
  route_configuration_digest KEYTEXT128,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(change_id, committed_url),
  CHECK((cache_id IS NULL AND route_id IS NULL
AND route_configuration_generation IS NULL
AND route_configuration_digest IS NULL)
OR(cache_id IS NOT NULL AND route_id IS NOT NULL
AND route_configuration_generation IS NOT NULL
AND route_configuration_digest IS NOT NULL)),
  FOREIGN KEY(route_id, cache_id, route_configuration_generation,
route_configuration_digest)
  REFERENCES route_configurations(route_id, cache_id,
configuration_generation, configuration_digest)
);

CREATE TABLE route_observations(
  route_id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER,
  cache_id INTEGER,
  configuration_generation INTEGER NOT NULL,
  configuration_digest KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  observed_at INTEGER NOT NULL,
  error LONGTEXT,
  FOREIGN KEY(route_id, registry_id, configuration_generation, configuration_digest)
  REFERENCES route_heads(route_id, registry_id, configuration_generation, configuration_digest),
  FOREIGN KEY(route_id, cache_id, configuration_generation, configuration_digest)
  REFERENCES route_heads(route_id, cache_id, configuration_generation, configuration_digest),
  CHECK(state IN('unknown', 'probing', 'healthy', 'degraded', 'unreachable', 'declared')),
  CHECK(state IN('degraded', 'unreachable') OR error IS NULL)
);

CREATE TABLE route_access_observations(
  route_id KEYTEXT64 PRIMARY KEY,
  configuration_generation INTEGER NOT NULL,
  configuration_digest KEYTEXT128 NOT NULL,
  access_policy_digest KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  observed_at INTEGER NOT NULL,
  error LONGTEXT,
  FOREIGN KEY(route_id, configuration_generation, configuration_digest, access_policy_digest)
  REFERENCES route_heads(route_id, configuration_generation, configuration_digest, access_policy_digest),
  CHECK(state IN('unknown', 'probing', 'verified', 'degraded', 'failed')),
  CHECK(state IN('degraded', 'failed') OR error IS NULL)
);

CREATE TABLE direct_route_evidence(
  route_id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER,
  cache_id INTEGER,
  configuration_generation INTEGER NOT NULL,
  configuration_digest KEYTEXT128 NOT NULL,
  endpoint_id KEYTEXT64 NOT NULL,
  endpoint_generation INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  gateway_id KEYTEXT64 NOT NULL,
  gateway_generation INTEGER NOT NULL,
  publication_manifest_id KEYTEXT64 NOT NULL,
  observed_at INTEGER NOT NULL,
  FOREIGN KEY(route_id, registry_id, configuration_generation, configuration_digest)
  REFERENCES route_heads(route_id, registry_id, configuration_generation, configuration_digest),
  FOREIGN KEY(route_id, cache_id, configuration_generation, configuration_digest)
  REFERENCES route_heads(route_id, cache_id, configuration_generation, configuration_digest),
  FOREIGN KEY(publication_manifest_id, placement_id, registry_id)
  REFERENCES placement_delivery_manifests(manifest_id, placement_id, registry_id),
  FOREIGN KEY(publication_manifest_id, placement_id, cache_id)
  REFERENCES placement_delivery_manifests(manifest_id, placement_id, cache_id)
);

CREATE INDEX egress_request_nonces_expiry
ON egress_request_nonces(expires_at);

CREATE INDEX webhook_deliveries_due_idx
ON webhook_deliveries(
  status,
  next_attempt_at,
  claim_expires_at
);

CREATE INDEX surface_placements_registry_idx
ON surface_placements(
  registry_id,
  read_order,
  id
);

CREATE INDEX surface_placements_cache_idx
ON surface_placements(
  cache_id,
  read_order,
  id
);

CREATE VIEW surface_placement_effective AS
    SELECT p.id,
           p.registry_id,
           p.cache_id,
           p.name,
           p.binding_id,
           p.prefix,
           CASE WHEN a.observed_placement_id = p.id THEN 'primary'
                WHEN p.kind = 'complete' THEN 'replica'
                ELSE p.kind END AS derived_role,
           COALESCE(o.state,
  'provisioning') AS state,
           COALESCE(o.completeness,
  'unknown') AS completeness,
           p.hash_range_start,
           p.hash_range_end,
           w.mutable_publication_id,
           CASE WHEN p.desired_state = 'active' AND p.desired_read_enabled = 1
                  AND o.state IN ('ready',
  'degraded')
                  AND o.completeness = 'complete' AND p.kind <> 'archive'
                THEN 1 ELSE 0 END AS effective_read_enabled,
           CASE WHEN a.observed_placement_id = p.id
                  AND a.observed_placement_id = a.desired_placement_id
                  AND a.observed_write_spec_version = a.desired_write_spec_version
                  AND a.observed_binding_write_revision = a.desired_binding_write_revision
                  AND a.observed_generation = a.desired_generation
                  AND a.reconciliation_state = 'ready'
                  AND p.kind = 'complete' AND p.desired_state = 'active'
                  AND o.state = 'ready' AND o.completeness = 'complete'
                  AND bwo.state = 'valid' AND bwr.writes_supported = 1
                  AND (p.requires_conditional_writes = 0
                    OR bwr.conditional_writes_supported = 1)
                THEN 1 ELSE 0 END AS effective_write_enabled,
           p.read_order,
           p.created_at,
           p.updated_at,
           p.resource_version,
           p.kind,
           p.desired_state,
           p.desired_read_enabled,
           p.write_spec_version,
           p.requires_conditional_writes,
           o.observed_at,
           o.observation_version,
           w.resource_version AS watermark_resource_version,
           w.pending_publication_id AS watermark_pending_publication_id,
           a.id AS write_authority_id,
           a.desired_placement_id AS authority_desired_placement_id,
           a.observed_placement_id AS authority_observed_placement_id,
           a.desired_write_spec_version AS authority_desired_write_spec_version,
           a.observed_write_spec_version AS authority_observed_write_spec_version,
           a.desired_binding_write_revision AS authority_desired_binding_write_revision,
           a.observed_binding_write_revision AS authority_observed_binding_write_revision,
           a.desired_generation AS authority_desired_generation,
           a.observed_generation AS authority_observed_generation,
           a.reconciliation_state AS authority_reconciliation_state
    FROM surface_placements p
    LEFT JOIN surface_placement_observations o ON o.placement_id = p.id
    LEFT JOIN registry_placement_publication_watermarks w ON w.placement_id = p.id
    LEFT JOIN surface_write_authorities a
      ON (a.registry_id = p.registry_id OR a.cache_id = p.cache_id)
    LEFT JOIN surface_placement_write_capabilities pc
      ON pc.placement_id = a.observed_placement_id
     AND pc.placement_write_spec_version = a.observed_write_spec_version
     AND pc.binding_write_revision = a.observed_binding_write_revision
    LEFT JOIN binding_write_revisions bwr
      ON bwr.binding_id = pc.binding_id
     AND bwr.revision = pc.binding_write_revision
    LEFT JOIN binding_write_observations bwo
      ON bwo.binding_id = bwr.binding_id
     AND bwo.revision = bwr.revision
/* surface_placement_effective(id,
  registry_id,
  cache_id,
  name,
  binding_id,
  prefix,
  derived_role,
  state,
  completeness,
  hash_range_start,
  hash_range_end,
  mutable_publication_id,
  effective_read_enabled,
  effective_write_enabled,
  read_order,
  created_at,
  updated_at,
  resource_version,
  kind,
  desired_state,
  desired_read_enabled,
  write_spec_version,
  requires_conditional_writes,
  observed_at,
  observation_version,
  watermark_resource_version,
  watermark_pending_publication_id,
  write_authority_id,
  authority_desired_placement_id,
  authority_observed_placement_id,
  authority_desired_write_spec_version,
  authority_observed_write_spec_version,
  authority_desired_binding_write_revision,
  authority_observed_binding_write_revision,
  authority_desired_generation,
  authority_observed_generation,
  authority_reconciliation_state) */;

CREATE INDEX registry_image_roots_object_idx
ON registry_image_roots(surface_object_id);

CREATE INDEX image_snapshot_leases_digest_idx
ON image_snapshot_leases(digest,
  expires_at);

CREATE INDEX registry_system_images_release_identity_idx
ON registry_system_images(registry_id,
  release,
  source_commit,
  verified_tag_oid);

CREATE INDEX manual_retention_roots_cache_idx
ON manual_retention_roots(
  cache_id,
  deleted_at,
  id
);

CREATE INDEX cache_root_reasons_cache_idx
ON cache_root_reasons(
  cache_id,
  store_hash,
  expires_at
);

CREATE INDEX topology_event_outbox_pending_idx
ON topology_event_outbox(materialized_at,
  occurred_at,
  event_id);

CREATE INDEX topology_operations_scope_idx
ON topology_operations(authorization_scope_key,
  created_at,
  operation_id);

CREATE INDEX operation_secondary_targets_resource_idx
ON operation_secondary_targets(target_kind,
  stable_id,
  operation_id);

CREATE INDEX topology_pin_resolution_jobs_state_idx
ON topology_pin_resolution_jobs(operation_id,
  state,
  pin_id);

CREATE UNIQUE INDEX topology_plans_request_idempotency_idx
ON topology_plans(
  actor_kind,
  actor_id,
  plan_kind,
  request_idempotency_key
);

CREATE UNIQUE INDEX bindings_scope_idx
ON bindings(
  id,
  owner_scope_key
);

CREATE INDEX delivery_attestation_nonces_expiry_idx
ON delivery_attestation_nonces(expires_at);

CREATE INDEX cache_inventory_candidate_identity
ON cache_inventory_narinfo_candidates(cache_id,
  generation,
  store_hash,
  identity_digest);

CREATE INDEX cache_objects_lifecycle_idx
ON cache_objects(cache_id,
  lifecycle_state,
  unreferenced_since,
  id);

CREATE INDEX cache_object_references_target_idx
ON cache_object_references(cache_id,
  referenced_store_hash);

CREATE INDEX cache_object_mutation_fences_active_idx
ON cache_object_mutation_fences(cache_id,
  state,
  store_hash);

CREATE INDEX object_deletion_jobs_due_idx
ON object_deletion_jobs(state,
  next_attempt_at,
  job_id);

CREATE INDEX object_deletion_attempt_receipts_job_idx
ON object_deletion_attempt_receipts(cache_id,
  job_id,
  attempt_number);

CREATE UNIQUE INDEX org_idp_configs_mutation_plan_idx
ON org_idp_configs(mutation_plan_id);

CREATE UNIQUE INDEX org_domains_mutation_plan_idx
ON org_domains(mutation_plan_id);

CREATE UNIQUE INDEX org_idp_configs_incarnation_idx
ON org_idp_configs(incarnation_id);

CREATE UNIQUE INDEX org_domains_incarnation_idx
ON org_domains(incarnation_id);

CREATE INDEX authorization_scope_ancestors_ancestor_idx
ON authorization_scope_ancestors(ancestor_scope_key,
  descendant_scope_key);

CREATE INDEX placement_scan_claims_expiry_idx
ON placement_scan_claims(lease_expires_at,
  operation_id);

CREATE INDEX worker_job_executions_state_lease
ON worker_job_executions(state,
  lease_expires_at);

CREATE INDEX registry_index_build_heads_state_lease
ON registry_index_build_heads(state,
  lease_expires_at);

CREATE INDEX registry_publication_manifest_sessions_lease
ON registry_publication_manifest_sessions(state,
  lease_expires_at);

CREATE INDEX release_artifacts_hash_idx
ON release_artifacts(store_hash,
  snapshot_id);

CREATE INDEX registry_catalog_artifacts_hash_idx
ON registry_catalog_artifacts(registry_id,
  source_revision,
  store_hash);

CREATE INDEX package_documentation_digest_idx
ON package_documentation(registry_id,
  document_sha256);

CREATE INDEX package_documentation_search_package_idx
ON package_documentation_search(registry_id,
  package_name,
  package_version,
  platform);

CREATE INDEX release_package_documentation_digest_idx
ON release_package_documentation(registry_id,
  document_sha256);

CREATE INDEX release_bundle_publications_registry_idx
  ON release_bundle_publications(registry_id,
  environment,
  committed_at);

CREATE INDEX release_channel_operations_manifest_idx
  ON release_channel_operations(registry_id,
  manifest_digest);

CREATE INDEX oci_blobs_surface_object_idx
ON oci_blobs(surface_object_id,
  registry_id);

CREATE INDEX oci_repository_objects_digest_idx
ON oci_repository_objects(registry_id,
  digest,
  repository_id);

CREATE INDEX oci_manifests_subject_idx
ON oci_manifests(registry_id,
  subject_digest,
  digest);

CREATE INDEX oci_descriptor_edges_target_idx
ON oci_descriptor_edges(registry_id,
  target_digest,
  manifest_digest);

CREATE INDEX oci_tags_digest_idx
ON oci_tags(registry_id,
  repository_id,
  digest);

CREATE INDEX oci_tag_history_repository_idx
ON oci_tag_history(repository_id,
  changed_at,
  id);

CREATE INDEX oci_release_roots_digest_idx
ON oci_release_roots(registry_id,
  index_digest);

CREATE INDEX oci_leases_digest_idx
ON oci_leases(registry_id,
  digest,
  expires_at);

CREATE INDEX oci_gc_generations_registry_idx
ON oci_gc_generations(registry_id,
  created_at);

CREATE INDEX oci_publications_expiry_idx
ON oci_publication_sessions(state,
  expires_at);

CREATE INDEX oci_publication_required_placements_registry_idx
ON oci_publication_required_placements(registry_id,
  placement_id,
  publication_id);

CREATE INDEX oci_publication_objects_digest_idx
ON oci_publication_objects(registry_id,
  digest,
  publication_id);

CREATE INDEX oci_publication_object_placements_evidence_idx
ON oci_publication_object_placements(
  registry_id,
  surface_object_id,
  placement_id,
  publication_id
);

CREATE INDEX oci_quota_reservations_registry_idx
ON oci_quota_reservations(registry_id,
  state,
  created_at);

CREATE INDEX oci_upload_sessions_cleanup_idx
ON oci_upload_sessions(cleanup_state,
  finished_at,
  id);

CREATE INDEX oci_image_config_platform_idx
ON oci_image_config_projections(
  registry_id,
  repository_id,
  root_digest,
  operating_system,
  architecture,
  variant
);

CREATE INDEX oci_release_layers_digest_idx
ON oci_release_layers(registry_id,
  digest,
  repository_id);

CREATE INDEX oci_admin_projection_reconcile_idx
ON oci_admin_projection_reconciliations(registry_id,
  state,
  root_digest);

CREATE INDEX oci_admin_mutations_registry_idx
ON oci_admin_mutations(registry_id,
  created_at,
  id);

CREATE INDEX oci_repositories_admin_list_idx
ON oci_repositories(registry_id,
  lifecycle_state,
  name,
  id);

CREATE INDEX oci_tag_history_admin_list_idx
ON oci_tag_history(registry_id,
  repository_id,
  name,
  changed_at,
  id);

CREATE INDEX oci_publications_admin_list_idx
ON oci_publication_sessions(registry_id,
  created_at,
  id);

CREATE INDEX oci_release_roots_admin_list_idx
ON oci_release_roots(registry_id,
  repository_id,
  created_at,
  release_tag);

CREATE INDEX oci_provider_inventories_placement_idx
ON oci_provider_inventory_generations(placement_id,
  completed_at,
  id);

CREATE INDEX oci_provider_inventory_entries_catalog_idx
ON oci_provider_inventory_entries(
  registry_id,
  object_digest,
  placement_id,
  generation_id
);

CREATE INDEX oci_provider_inventory_entries_untracked_idx
ON oci_provider_inventory_entries(
  registry_id,
  classification,
  deleted_at,
  generation_id
);

CREATE INDEX oci_gc_runs_registry_idx
ON oci_gc_runs(registry_id,
  created_at,
  id);

CREATE INDEX oci_gc_runs_state_idx
ON oci_gc_runs(state,
  created_at,
  id);

CREATE INDEX oci_gc_actions_claim_idx
ON oci_gc_placement_actions(state,
  next_attempt_at,
  run_id,
  id);

CREATE INDEX oci_gc_snapshot_lease_holds_registry_idx
ON oci_gc_snapshot_lease_holds(registry_id,
  snapshot_digest);

CREATE INDEX oci_blobs_gc_eligibility_idx
ON oci_blobs(registry_id,
  lifecycle_state,
  unreferenced_since,
  digest);

CREATE INDEX oci_registry_purge_fence_plans_state_idx
ON oci_registry_purge_fence_plans(state,
  expires_at,
  id);

CREATE INDEX oci_untracked_repairs_state_idx
ON oci_untracked_repair_plans(state,
  created_at,
  id);

CREATE INDEX release_browse_tree_children_idx
ON release_browse_tree_nodes(registry_id,
  source_commit,
  parent_key,
  sort_key,
  node_key);

CREATE INDEX release_browse_tree_variants_idx
ON release_browse_tree_entries(registry_id,
  source_commit,
  node_key,
  entry_key);

INSERT INTO hub_schema_identity (identity)
VALUES ('aos-hub/production-baseline/1');

INSERT INTO write_recovery_cursors (recovery_kind,
  after_expires_at,
  after_ticket_id,
  resource_version,
  updated_at)
VALUES ('cache',
  -9007199254740991,
  '',
  1,
  0);

INSERT INTO consumer_scope_grant_events (event_id,
  resource_kind,
  resource_stable_id,
  resource_generation_key,
  consumer_scope_key,
  grant_generation,
  transition,
  previous_state,
  resulting_state,
  actor_id,
  occurred_at,
  request_id)
VALUES ('grant-event:instance-public-instance',
  'network_policy',
  'instance:public',
  0,
  'instance',
  1,
  'granted',
  NULL,
  'active',
  'system:schema',
  0,
  'schema:instance-public');

INSERT INTO oci_phase5_upgrade_guard (id,
  marker)
VALUES ('phase5',
  0);

INSERT INTO authorization_scopes (scope_key,
  kind,
  org_id,
  parent_scope_key,
  resource_stable_id,
  owner_guard_version,
  retired_at,
  created_at)
VALUES ('instance',
  'instance',
  NULL,
  NULL,
  'instance',
  1,
  NULL,
  0);

INSERT INTO network_policies (id,
  org_id,
  owner_scope_key,
  name,
  kind,
  identity_spec_json,
  identity_fingerprint,
  resource_version,
  created_at,
  updated_at)
VALUES ('instance:public',
  NULL,
  'instance',
  'Public Internet',
  'public',
  '{"kind":"public"}',
  'a45d7088ef1cb3f42b0f7c1284e56a781daabc736ecce73134b8e4f53078c08d',
  1,
  0,
  0);

INSERT INTO authorization_scope_ancestors (descendant_scope_key,
  ancestor_scope_key,
  depth)
VALUES ('instance',
  'instance',
  0);

INSERT INTO network_policy_revisions (boundary_id,
  revision,
  protected_transport_required,
  trusted_ingress_kind,
  trusted_ingress_configuration,
  source_allowlist_cidrs,
  probe_location_configuration,
  content_digest,
  created_by,
  created_at)
VALUES ('instance:public',
  1,
  0,
  'none',
  '{}',
  NULL,
  '',
  '04f0d6f002c20c3711ec06812007e824b6c56782afd71288992894e5c5dce0cd',
  'system:schema',
  0);

INSERT INTO network_policy_consumer_scopes (boundary_id,
  consumer_scope_key,
  grant_generation,
  grant_kind,
  state,
  granted_by,
  granted_at,
  revoked_by,
  revoked_at,
  resource_version)
VALUES ('instance:public',
  'instance',
  1,
  'instance_default',
  'active',
  'system:schema',
  0,
  NULL,
  NULL,
  1);

INSERT INTO network_policy_observations (boundary_id,
  revision,
  state,
  protected_transport_observed,
  trusted_ingress_observed,
  observed_at,
  error)
VALUES ('instance:public',
  1,
  'verified',
  0,
  'none',
  0,
  NULL);

INSERT INTO network_policy_revision_lifecycle (boundary_id,
  revision,
  state,
  activation_mode,
  consumer_version,
  activated_at,
  retired_at,
  resource_version)
VALUES ('instance:public',
  1,
  'active',
  'system',
  0,
  0,
  NULL,
  1);

INSERT INTO network_policy_defaults (boundary_id,
  revision,
  state,
  resource_version,
  updated_at)
VALUES ('instance:public',
  1,
  'active',
  1,
  0);
