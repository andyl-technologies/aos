-- Immutable row incarnations close ABA across delete/recreate. Existing rows
-- remain NULL until their first reviewed mutation; null-safe CAS treats that
-- legacy incarnation as distinct from every reviewed recreation.
ALTER TABLE org_idp_configs ADD COLUMN incarnation_id KEYTEXT64;
CREATE UNIQUE INDEX org_idp_configs_incarnation_idx
ON org_idp_configs(incarnation_id);

ALTER TABLE org_domains ADD COLUMN incarnation_id KEYTEXT64;
CREATE UNIQUE INDEX org_domains_incarnation_idx
ON org_domains(incarnation_id);
