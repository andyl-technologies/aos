-- Supports instance/organization operation inventory by walking from one
-- immutable ancestor scope to every descendant-owned operation.
CREATE INDEX authorization_scope_ancestors_ancestor_idx
ON authorization_scope_ancestors(ancestor_scope_key, descendant_scope_key);
