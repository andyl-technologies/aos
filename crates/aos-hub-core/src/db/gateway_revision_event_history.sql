-- Preserve gateway desired-generation history independently of the mutable
-- desired pointer on the gateway identity. The original composite foreign key
-- made every second gateway generation impossible because the generation-one
-- event continued to reference the previous gateway resource version.
ALTER TABLE gateway_revision_events RENAME TO gateway_revision_events_legacy;

CREATE TABLE gateway_revision_events(
  event_id KEYTEXT64 PRIMARY KEY,
  gateway_id KEYTEXT64 NOT NULL,
  generation INTEGER NOT NULL,
  gateway_resource_version INTEGER NOT NULL,
  transition KEYTEXT16 NOT NULL,
  actor_id KEYTEXT128 NOT NULL,
  occurred_at INTEGER NOT NULL,
  UNIQUE(gateway_id, generation),
  FOREIGN KEY(gateway_id, generation)
  REFERENCES gateway_revisions(gateway_id, generation),
  CHECK(transition = 'desired')
);

INSERT INTO gateway_revision_events
  (event_id, gateway_id, generation, gateway_resource_version,
   transition, actor_id, occurred_at)
SELECT event_id, gateway_id, generation, gateway_resource_version,
       transition, actor_id, occurred_at
FROM gateway_revision_events_legacy;

DROP TABLE gateway_revision_events_legacy;
