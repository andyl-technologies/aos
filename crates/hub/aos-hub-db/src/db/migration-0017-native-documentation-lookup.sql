-- Resolve immutable documentation artifacts without scanning release catalogs.
CREATE INDEX release_native_documentation_by_digest
  ON release_native_documentation(registry_id, document_sha256, source_commit);
