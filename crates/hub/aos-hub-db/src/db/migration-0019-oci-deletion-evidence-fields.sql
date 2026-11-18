-- OCI deletion rows store their recorded provider fields directly; the derived
-- digest over those fields is no longer kept.
ALTER TABLE oci_gc_deletion_evidence DROP COLUMN evidence_digest;
ALTER TABLE oci_untracked_repair_evidence DROP COLUMN evidence_digest;
