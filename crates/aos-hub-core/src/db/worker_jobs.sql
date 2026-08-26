-- Durable at-least-once queue admission. The operation identity is carried by
-- the v2 queue envelope and remains stable across delivery retries.
CREATE TABLE worker_job_executions(
  operation_id KEYTEXT64 PRIMARY KEY,
  job_kind KEYTEXT64 NOT NULL,
  payload_digest KEYTEXT64 NOT NULL,
  state KEYTEXT16 NOT NULL DEFAULT 'pending',
  claim_token KEYTEXT64,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  lease_expires_at INTEGER,
  last_error LONGTEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  completed_at INTEGER,
  CHECK(state IN('pending', 'running', 'completed')),
  CHECK(attempt_count >= 0),
  CHECK((state = 'pending' AND claim_token IS NULL AND lease_expires_at IS NULL
         AND completed_at IS NULL)
     OR (state = 'running' AND claim_token IS NOT NULL
         AND lease_expires_at IS NOT NULL AND completed_at IS NULL)
     OR (state = 'completed' AND claim_token IS NULL
         AND lease_expires_at IS NULL AND completed_at IS NOT NULL))
);
CREATE INDEX worker_job_executions_state_lease
ON worker_job_executions(state, lease_expires_at);
