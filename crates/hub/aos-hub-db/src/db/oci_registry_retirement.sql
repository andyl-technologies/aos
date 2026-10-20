-- Reviewed OCI catalog retirement.
--
-- A retiring GC plan treats every signed-release, tag, and history root of one
-- registry as retired, so the whole catalog becomes collectable ahead of
-- registry deletion. The flag is frozen into the run so apply, finalization,
-- and the indexer guard revalidate the same reviewed intent. The statement is
-- additive and replay-safe under the MySQL migration helpers.
ALTER TABLE oci_gc_runs ADD COLUMN retire_registry INTEGER NOT NULL DEFAULT 0;
