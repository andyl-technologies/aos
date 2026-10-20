-- Upload versions distinguish byte-identical R2 recreations. Legacy nullable
-- rows require a new inventory and review before first destructive dispatch.
ALTER TABLE oci_provider_inventory_entries ADD COLUMN provider_version KEYTEXT512;
ALTER TABLE oci_gc_placement_actions ADD COLUMN expected_provider_version KEYTEXT512;
ALTER TABLE cache_inventory_listed_objects ADD COLUMN provider_version KEYTEXT512;
ALTER TABLE cache_inventory_object_observations ADD COLUMN provider_version KEYTEXT512;
ALTER TABLE object_placements ADD COLUMN provider_version KEYTEXT512;
ALTER TABLE cache_gc_plan_actions ADD COLUMN expected_provider_version KEYTEXT512;
ALTER TABLE object_deletion_jobs ADD COLUMN expected_provider_version KEYTEXT512;
ALTER TABLE object_deletion_attempt_receipts ADD COLUMN expected_provider_version KEYTEXT512;
