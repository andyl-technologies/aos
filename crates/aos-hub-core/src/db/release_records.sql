-- The public release record served beside a release manifest, retained per
-- verified tag so a retag replaces it. The signed qualification envelope inside
-- is verified against the deployment's qualification keys when read, never
-- trusted from storage alone.
CREATE TABLE release_records(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  tag_oid KEYTEXT64 NOT NULL,
  record_json LONGTEXT NOT NULL,
  PRIMARY KEY(registry_id, tag_oid)
);
