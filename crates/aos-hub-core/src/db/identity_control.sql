-- Retained-control fencing for organization identity-provider and email-domain
-- mutations. Human-facing values are mutable, while the organization/domain
-- identity remains stable and every write advances an exact resource version.
ALTER TABLE org_idp_configs ADD COLUMN resource_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE org_idp_configs ADD COLUMN mutation_plan_id KEYTEXT64;
CREATE UNIQUE INDEX org_idp_configs_mutation_plan_idx
ON org_idp_configs(mutation_plan_id);

ALTER TABLE org_domains ADD COLUMN resource_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE org_domains ADD COLUMN mutation_plan_id KEYTEXT64;
CREATE UNIQUE INDEX org_domains_mutation_plan_idx
ON org_domains(mutation_plan_id);
