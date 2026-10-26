CREATE TABLE binding_id_tombstones(
  id INTEGER PRIMARY KEY,
  stable_id KEYTEXT64 NOT NULL,
  owner_scope_key KEYTEXT64 NOT NULL,
  deleted_at INTEGER NOT NULL
);
