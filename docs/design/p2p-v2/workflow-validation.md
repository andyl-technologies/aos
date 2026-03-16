# Workflow Validation

When a workflow is submitted via `/aos/workflow/run/1.0.0`, the bootstrap node
validates the workflow spec before creating the store object and announcing
the workflow. Validation is fail-fast — the first error rejects the entire
workflow.

## Validation Stages

### 1. Structural Validation

Basic well-formedness checks on the `WorkflowSpec` protobuf:

- **Non-empty steps:** the workflow must contain at least one step.
- **Unique step IDs:** no two steps may share the same `id` string.
- **Valid step references:** every step ID in a `deps` list must reference
  an existing step in the workflow.
- **Non-empty output_hash:** every `fetch` and `build` step must specify
  an `output_hash`. Every `input` step must specify a `store_hash`.
- **Valid action types:** each step must have exactly one action type set
  (`input`, `fetch`, `build`, `await_workflow`, `decision`, or `run`).
- **Valid action types:** each step must have exactly one action type set.
- **RunStep validation:** `run` steps must reference a valid `spec_hash`. The
  referenced store object must exist and must be a RunSpec (not BuildSpec or
  FetchSpec).
- **Deadline in future:** `deadline` must be greater than the current time.
- **Expiration after deadline:** `expiration` must be >= `deadline`.

### 2. Graph Validation

Dependency graph analysis:

- **Acyclicity:** the step dependency graph must be a DAG. A topological sort
  must succeed. If a cycle is detected, the validation fails with the cycle
  path.
- **Reachability:** every step must be reachable from at least one root step
  (a step with empty `deps`). Unreachable steps indicate a disconnected
  subgraph, which is an error.
- **Max steps:** the total number of steps must not exceed the daemon's
  `workflows.max_steps` limit.
- **Max depth:** the longest path through the DAG (critical path) must not
  exceed `workflows.max_depth`. This bounds the transition log size.

### 3. Input Validation

All `input` source types must reference store objects that currently exist:

- For each `input` step:
  - Query `get_providers` on `aos:store:object:{store_hash}` in the DHT.
  - If no providers exist AND the object is not in the local store, reject
    with error: `"input store object {store_hash} not found"`.
- This ensures all inputs are available before the workflow starts. The
  client is expected to upload all inputs (via `/aos/store/upload/1.0.0`)
  before submitting the workflow.

### 4. Fetch Source Validation

All `fetch` source types must have valid configuration:

- **Non-empty URLs:** at least one URL must be specified.
- **Valid URL format:** each URL must be parseable and use a supported scheme
  (http, https, ftp, ftps).
- **Hash present:** the `hash` field must be non-empty and in SRI format
  (e.g., `sha256-...`).
- **Domain filtering:** each URL's domain must pass the daemon's domain
  filter (`store.fetch.allowed_domains` / `store.fetch.blocked_domains`).
  If a URL is blocked, the step is rejected (even if other URLs are valid).

### 5. Cross-Workflow Validation

All `await_workflow` steps must reference valid workflows:

- For each `await_workflow` step:
  - Query `get_providers` on `aos:workflow:run:{workflow_id}` in the DHT.
  - OR check the local WorkflowDB for the referenced workflow.
  - If the workflow does not exist (no providers, not in local DB), reject
    with error: `"referenced workflow {workflow_id} not found"`.
  - If `step_id` is specified, validate that it exists in the referenced
    workflow's spec (requires fetching the spec via
    `/aos/workflow/info/1.0.0`).
- **Cross-workflow cycle detection:** the daemon maintains a cross-workflow
  dependency graph in `WorkflowDB.workflow_deps_db`. On submission:
  - Insert edges: this workflow → each `await_workflow` target.
  - Run topological sort on the full cross-workflow graph.
  - If a cycle is detected (W1 awaits W2 which awaits W1), reject with
    error: `"cross-workflow cycle detected: W1 → W2 → W1"`.

### 6. Resource Validation

Check that the workflow's resource requirements are feasible:

- **Decision step conditions:** `store_object_exists` conditions must
  reference valid store hash formats (not empty strings or malformed hashes).
- **Step timeouts:** if specified, must be positive and not exceed the
  workflow deadline.
- **Workflow deadline:** must be at least some minimum duration from now
  (e.g., 60 seconds) to allow for startup overhead.

### 7. Capacity Validation

Check daemon-level limits:

- **Max active workflows:** the daemon's `workflows.max_concurrent` limit
  must not be exceeded. If the daemon is already tracking the maximum number
  of workflows, reject with `503 Service Unavailable`.
- **Store capacity:** the daemon should have sufficient free store space
  for the workflow's expected outputs. This is a soft check (estimate based
  on the number of build steps and average output size).

## Validation Error Response

When validation fails, the daemon returns a `StreamError` in the
`WorkflowRunStatus` response with:

- **Code:** `400` for structural/graph/input/fetch errors, `409` for duplicate
  workflow, `503` for capacity limits.
- **Message:** human-readable error describing the specific validation failure,
  including the step ID where applicable.

Example errors:

```
400: "cycle detected in step dependencies: build-gcc → build-glibc → build-gcc"
400: "input store object abc123 not found for step src-linux-headers"
400: "fetch URL https://blocked.example.com/file.tar.gz blocked by domain filter for step src-gcc"
400: "workflow depth 600 exceeds max_depth limit of 500"
409: "workflow abc123 is already running"
503: "max_concurrent workflows limit (100) reached"
```

## Validation in the Run Protocol

The `/aos/workflow/run/1.0.0` protocol flow with validation:

1. **Receive `WorkflowRunRequest`** with the workflow spec (JSON-encoded
   protobuf) and UCAN.
2. **Authenticate.** Verify UCAN against `/aos/workflow/run`.
3. **Parse spec.** Decode the JSON-encoded `WorkflowSpec` protobuf.
4. **Run validation stages 1-7** in order. Fail-fast on first error.
5. **Check for duplicates.** Compute `workflow_id = hash(spec)`. Query DHT
   for existing providers.
6. **Create store object.** Serialize the spec as a store object (single
   `workflow.json` file), write to local store, publish to DHT.
7. **Ingest workflow.** Write to WorkflowDB, create state topic, advertise
   as tracker.
8. **Announce.** Publish `WorkflowPost{create}` to `workflows/announce`.
9. **Respond.** Stream `WorkflowRunStatus` progress messages, ending with
   `WorkflowRunStarted` on success.

Validation (steps 3-5) completes before any store writes or gossipsub
messages. If validation fails, no side effects occur.

## Relationship to Other Docs

- [workflow.md](workflow.md) -- workflow execution model, state machine.
- [workflow-spec.md](workflow-spec.md) -- step types, source types, spec format.
- [protocol.md](protocol.md) -- `WorkflowRunRequest`, `WorkflowRunStatus`
  protobuf definitions.
- [daemon.md](daemon.md) -- `[workflows]` configuration limits.
- [storage.md](storage.md) -- WorkflowDB schema (`workflow_deps_db` for cycle
  detection).
