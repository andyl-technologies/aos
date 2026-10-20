-- Instance-owned OCI root routes and per-registry OCI namespaces.
--
-- Standard Distribution clients always request `https://<host>/v2/<name>/...`
-- at the host root, so one hostname's OCI surface used to be bound to exactly
-- one registry through a registry-owned route. An instance OCI route is owned
-- by the deployment instead: it sits at a host root, serves only OCI, and
-- dispatches `<name>` by the longest leading path segments that equal the slug
-- of a registry whose namespace is enabled. The route's permanent URL
-- reservation therefore survives registry creation and deletion.
--
-- Both statements are additive and replay-safe under the MySQL migration
-- helpers: `CREATE TABLE` becomes `CREATE TABLE IF NOT EXISTS` on replay.

-- One instance OCI route per endpoint. The route never references a registry
-- except through `default_registry_id`, which names the registry served for
-- repository names that carry no enabled namespace prefix. That reference is
-- restrictive on purpose: a registry that still answers unnamespaced
-- references cannot be deleted underneath the route.
CREATE TABLE instance_oci_routes(
  id KEYTEXT64 PRIMARY KEY,
  url_reservation_id KEYTEXT64 NOT NULL REFERENCES route_url_reservations(id),
  resource_version INTEGER NOT NULL DEFAULT 1,
  endpoint_id KEYTEXT64 NOT NULL UNIQUE,
  endpoint_generation INTEGER NOT NULL,
  endpoint_ingress_kind KEYTEXT16 NOT NULL,
  canonical_rendered_url LONGTEXT NOT NULL,
  access_policy_kind KEYTEXT32 NOT NULL,
  access_policy_json LONGTEXT NOT NULL,
  access_policy_digest KEYTEXT128 NOT NULL,
  default_registry_id INTEGER REFERENCES registries(id),
  enabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(endpoint_id, endpoint_generation, endpoint_ingress_kind)
  REFERENCES endpoint_revisions(endpoint_id, generation, ingress_kind),
  CHECK(endpoint_ingress_kind IN('hub', 'layer7')),
  CHECK(access_policy_kind IN('public', 'hub_auth')),
  CHECK(enabled IN(0, 1))
);

-- Reviewed per-registry OCI exposure through instance routes. A missing row
-- means the namespace is disabled. An enabled namespace blocks catalog
-- retirement and registry deletion exactly like an enabled registry-bound OCI
-- route does.
CREATE TABLE registry_oci_namespaces(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  enabled INTEGER NOT NULL DEFAULT 0,
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK(enabled IN(0, 1))
);
