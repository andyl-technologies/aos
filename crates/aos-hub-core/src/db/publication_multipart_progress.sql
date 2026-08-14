-- Multipart publication uploads were introduced before incremental digest and
-- concurrency state. Keep those additions in their own forward migration so
-- already-migrated deployments receive the same columns as fresh databases.
ALTER TABLE registry_publication_multipart_uploads
  ADD COLUMN hashed_size INTEGER NOT NULL DEFAULT 0;
ALTER TABLE registry_publication_multipart_uploads
  ADD COLUMN sha256_state LONGTEXT NOT NULL
    DEFAULT '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
ALTER TABLE registry_publication_multipart_uploads
  ADD COLUMN pending_part INTEGER;
ALTER TABLE registry_publication_multipart_uploads
  ADD COLUMN pending_hash LONGTEXT;
ALTER TABLE registry_publication_multipart_uploads
  ADD COLUMN pending_token KEYTEXT64;
ALTER TABLE registry_publication_multipart_uploads
  ADD COLUMN pending_since INTEGER;
ALTER TABLE registry_publication_multipart_uploads
  ADD COLUMN completion_token KEYTEXT64;
ALTER TABLE registry_publication_multipart_uploads
  ADD COLUMN completion_since INTEGER;
ALTER TABLE registry_publication_multipart_backends
  ADD COLUMN completion_etag LONGTEXT;
