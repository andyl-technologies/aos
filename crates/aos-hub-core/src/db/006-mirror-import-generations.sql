-- Retain one exact Native business operation for each unresolved mirror path.
-- Nullable index fields permit typed legacy backfill without rewriting originals.
ALTER TABLE mirror_import_objects ADD COLUMN source_path LONGTEXT;
ALTER TABLE mirror_import_objects ADD COLUMN source_path_digest KEYTEXT64
  CHECK ((source_path IS NULL AND source_path_digest IS NULL)
    OR (source_path IS NOT NULL AND length(source_path) > 0
      AND source_path_digest IS NOT NULL AND length(source_path_digest) = 64));
ALTER TABLE mirror_import_objects ADD COLUMN copy_operation_id KEYTEXT64
  CHECK (copy_operation_id IS NULL OR length(copy_operation_id) = 32);

CREATE UNIQUE INDEX mirror_import_active_source_idx
  ON mirror_import_objects(registry_id, source_path_digest);
