-- Derived browse data is addressed by the verified source commit or document
-- digest. Publishing an index selects these rows through the existing signed
-- release and complete artifact snapshot; preparing rows cannot publish them.
CREATE TABLE release_browse_catalogs(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  source_commit KEYTEXT64 NOT NULL,
  packages_json TEXT NOT NULL,
  content_digest KEYTEXT64 NOT NULL,
  package_count INTEGER NOT NULL,
  documentation_count INTEGER NOT NULL,
  default_release KEYTEXT255,
  PRIMARY KEY(registry_id, source_commit)
);

-- Preserve authenticated tag prose independently of mutable channel state.
CREATE TABLE release_browse_notes(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  tag_oid KEYTEXT64 NOT NULL,
  body TEXT NOT NULL,
  PRIMARY KEY(registry_id, tag_oid)
);

-- One row per structural path prefix, including the empty configuration root.
-- Child ordering and cursors use indexed byte-exact keys, not OFFSET scans.
CREATE TABLE release_browse_tree_nodes(
  registry_id INTEGER NOT NULL,
  source_commit KEYTEXT64 NOT NULL,
  node_key KEYTEXT64 NOT NULL,
  parent_key KEYTEXT64,
  path_json TEXT NOT NULL,
  label KEYTEXT1024 NOT NULL,
  sort_key KEYTEXT1024 NOT NULL,
  child_count INTEGER NOT NULL,
  entry_count INTEGER NOT NULL,
  PRIMARY KEY(registry_id, source_commit, node_key),
  FOREIGN KEY(registry_id, source_commit)
    REFERENCES release_browse_catalogs(registry_id, source_commit) ON DELETE CASCADE
);
CREATE INDEX release_browse_tree_children_idx
ON release_browse_tree_nodes(registry_id, source_commit, parent_key, sort_key, node_key);

CREATE TABLE release_browse_tree_entries(
  registry_id INTEGER NOT NULL,
  source_commit KEYTEXT64 NOT NULL,
  entry_key KEYTEXT64 NOT NULL,
  node_key KEYTEXT64,
  document_sha256 KEYTEXT128 NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  package_version KEYTEXT64 NOT NULL,
  platform KEYTEXT64 NOT NULL,
  kind KEYTEXT32 NOT NULL,
  document_key TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  type_signature TEXT,
  PRIMARY KEY(registry_id, source_commit, entry_key),
  FOREIGN KEY(registry_id, source_commit)
    REFERENCES release_browse_catalogs(registry_id, source_commit) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, source_commit, node_key)
    REFERENCES release_browse_tree_nodes(registry_id, source_commit, node_key) ON DELETE CASCADE
);
CREATE INDEX release_browse_tree_variants_idx
ON release_browse_tree_entries(registry_id, source_commit, node_key, entry_key);

-- Prefix-searchable tokens keep search bounded independently of document size.
CREATE TABLE release_browse_search_terms(
  registry_id INTEGER NOT NULL,
  source_commit KEYTEXT64 NOT NULL,
  term KEYTEXT512 NOT NULL,
  entry_key KEYTEXT64 NOT NULL,
  weight INTEGER NOT NULL,
  PRIMARY KEY(registry_id, source_commit, term, entry_key),
  FOREIGN KEY(registry_id, source_commit, entry_key)
    REFERENCES release_browse_tree_entries(registry_id, source_commit, entry_key) ON DELETE CASCADE
);

-- Precomputed ancestry makes searches within any subtree an indexed join.
CREATE TABLE release_browse_tree_ancestors(
  registry_id INTEGER NOT NULL,
  source_commit KEYTEXT64 NOT NULL,
  ancestor_key KEYTEXT64 NOT NULL,
  node_key KEYTEXT64 NOT NULL,
  PRIMARY KEY(registry_id, source_commit, ancestor_key, node_key),
  FOREIGN KEY(registry_id, source_commit)
    REFERENCES release_browse_catalogs(registry_id, source_commit) ON DELETE CASCADE
);
