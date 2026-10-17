-- Nullable, bounded application-validated OCI inventory continuation.
-- Current serving initialization remains reset-only; historical schemas stay immutable.
ALTER TABLE oci_provider_inventory_generations ADD COLUMN object_progress BLOB;
