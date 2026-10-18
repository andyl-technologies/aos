-- Channel advances keyed by per-train channel names such as candidate-2026.12.
--
-- The baseline channel ledger admits only the three bare channel kinds and a
-- 16-byte key, so it cannot record a per-train channel. SQLite cannot relax a
-- constraint in place, and MySQL commits every DDL statement, so a
-- rename-and-drop rebuild could not be replayed after an interruption. This
-- migration is additive instead: it creates the successor ledger, copies every
-- retained operation, and leaves the baseline ledger frozen and unused. Each
-- statement is replay-safe under the MySQL migration helpers.
--
-- The Hub validates exact channel syntax before every write. The kind check
-- below is a coarse database guard, not the syntax authority.
--
-- publication_receipt_digest names the receipt that authorized the advance on
-- this deployment: the promoted production receipt on the production
-- deployment, or the committed staging receipt on the staging deployment.
CREATE TABLE release_channel_advances(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  channel KEYTEXT32 NOT NULL,
  prior_generation INTEGER NOT NULL,
  new_generation INTEGER NOT NULL,
  first_partition INTEGER NOT NULL,
  last_partition INTEGER NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  publication_receipt_digest KEYTEXT128 NOT NULL REFERENCES release_bundle_publications(receipt_digest) ON DELETE RESTRICT ON UPDATE RESTRICT,
  operation_digest KEYTEXT128 NOT NULL UNIQUE,
  receipt_json LONGTEXT NOT NULL,
  committed_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, channel, new_generation),
  CHECK(channel IN('edge', 'candidate', 'stable')
    OR substr(channel, 1, 5) = 'edge-'
    OR substr(channel, 1, 10) = 'candidate-'
    OR substr(channel, 1, 7) = 'stable-'),
  CHECK(prior_generation >= 0),
  CHECK(new_generation = prior_generation + 1),
  CHECK(first_partition >= 0 AND first_partition <= last_partition AND last_partition <= 255)
);

INSERT INTO release_channel_advances
  (registry_id, channel, prior_generation, new_generation, first_partition,
   last_partition, manifest_digest, publication_receipt_digest,
   operation_digest, receipt_json, committed_at)
SELECT registry_id, channel, prior_generation, new_generation, first_partition,
       last_partition, manifest_digest, production_receipt_digest,
       operation_digest, receipt_json, committed_at
FROM release_channel_operations;

CREATE INDEX release_channel_advances_manifest_idx
  ON release_channel_advances(registry_id,
  manifest_digest);
