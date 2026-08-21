-- Organizations created before quota reservations became transactional may
-- not have a usage accumulator. Preserve the API's historical missing-row
-- semantics (zero usage) while making every future reservation atomic.
INSERT INTO org_usage (org_id, used_bytes, object_count, updated_at)
SELECT id, 0, 0, 0
FROM orgs
WHERE NOT EXISTS (
  SELECT 1 FROM org_usage WHERE org_usage.org_id = orgs.id
);
