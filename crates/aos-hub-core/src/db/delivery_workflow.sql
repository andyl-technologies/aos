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
CREATE INDEX delivery_workflows_registry ON delivery_workflows(registry_id, workflow_id);
CREATE INDEX delivery_workflows_cache ON delivery_workflows(cache_id, workflow_id);
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
