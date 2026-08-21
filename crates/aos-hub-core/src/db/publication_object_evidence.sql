CREATE TABLE registry_publication_object_evidence(
  publication_id KEYTEXT64 NOT NULL,
  surface_object_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  observed_hash KEYTEXT128 NOT NULL,
  observed_size INTEGER NOT NULL,
  strong_etag KEYTEXT255,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY(publication_id, surface_object_id, placement_id),
  FOREIGN KEY(publication_id, surface_object_id)
  REFERENCES registry_publication_objects(publication_id, surface_object_id)
  ON DELETE CASCADE,
  FOREIGN KEY(publication_id, placement_id)
  REFERENCES registry_publication_placements(publication_id, placement_id)
  ON DELETE CASCADE,
  CHECK(observed_size >= 0)
);

INSERT INTO registry_publication_object_evidence
  (publication_id, surface_object_id, placement_id, observed_hash,
   observed_size, strong_etag, observed_at)
SELECT publication.publication_id, declared.surface_object_id,
       required.placement_id, presence.observed_hash,
       presence.observed_size, presence.etag, presence.observed_at
FROM registry_publications publication
JOIN registry_publication_objects declared
  ON declared.publication_id = publication.publication_id
JOIN registry_publication_placements required
  ON required.publication_id = publication.publication_id
JOIN object_placements presence
  ON presence.surface_object_id = declared.surface_object_id
 AND presence.placement_id = required.placement_id
 AND presence.registry_id = publication.registry_id
WHERE presence.state = 'present'
  AND presence.observed_hash = declared.expected_hash
  AND presence.observed_size = declared.expected_size
  AND presence.etag IS NOT NULL
  AND presence.observed_inventory_generation = publication.ordinal;
