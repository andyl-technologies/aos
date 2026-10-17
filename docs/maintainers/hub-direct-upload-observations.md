# Direct upload runtime observations

Worker console lines beginning with `direct_upload_observation ` contain one
closed JSON event. The schema lives in
`crates/aos-hub-worker/src/direct_upload/observation.rs`. Events describe actual
runtime boundaries; they do not authorize publication or qualify a deployment.

## Correlation and privacy

Each event has `version`, `kind`, `scope`, actual UTC `atMillis`, a participating
`isolateDigest`, and the compiled `sourceDigest`. A missing compiled digest in a
development build is `null`, not a fabricated source identity. Deployment and
script identity must also be retained in the actual installation/discovery
receipt for the process producing the logs.

All identifier fields are SHA-256 commitments. `sessionDigest` hashes the
original session ID and `originalDigest` hashes its immutable logical
fingerprint. Object events also commit the client operation, placement and
physical verification operation. Queue events retain a separate
`completeOperationDigest`. No object paths, URLs, provider receipts, credential
references, signatures, credentials or body text are emitted.

`object.dependencyPhase` is the retained original admission phase. `queueClass`
is `bulk` for `content`, and `metadata` for both `leaf_metadata` and `visibility`.
The queue consumer checks the actual configured queue before running the job.
Visibility JSON business uploads must be identified by their own originals;
isolated narinfo qualification jobs are not evidence for that workload.

## Event boundaries

- `control_request`: the exact signed metadata envelope offered to the Native
  transport. `control.step` distinguishes Admission, Status, GrantParts,
  ReportParts, Freeze, Baseline, Promote, Commit and Abort boundaries. A batch
  carries at most 64 original session commitments.
- `control_reply`: metadata bytes returned by the transport. `positive` means
  the reply passed independent signature/context/freshness validation.
  Transport failure is `unknown` with `bytes: null`, never an inferred empty
  reply. Request, public-body and signed-body commitments are retained;
  observed reply bytes have their own commitment.
- `queue_enqueue`: pending immediately before Queue.send, then positive after
  the SDK send promise resolves or unknown on failure, with the same attempt
  commitment. This records the returned SDK acceptance, not an independent
  queue-server readback, verification or durable buffered delivery.
- `queue_start`: after actual accepted object-capacity admission, before source
  work. Aggregate, bulk and metadata object counts describe that isolate.
- `queue_finish`: after the immutable verification result has been durably
  retained, or after a failed attempt. `replayed: true` explicitly identifies a
  retained positive receipt; it is not fresh verification.
- `queue_ack` / `queue_retry`: immediately after invoking the local queue
  acknowledgement/retry API. They do not claim provider-side durable delivery.
- `provider_read_start` / `provider_read_finish`: surround actual stream
  consumption. `readKind` distinguishes full integrity verification from a
  bounded semantic reread. `bytes` counts actual JavaScript BYOB views, including
  the measured prefix of a failed/cancelled read. It never copies the declared
  object length into an observed byte count.

Control directions are `worker_to_native` and `native_to_worker`; their counts
refer only to typed logical metadata envelopes (`dataKind: logical_metadata`). Source read direction is
`provider_to_worker`. Queue message byte counts are compact metadata and have
no network direction. Client-to-provider UploadPart bytes are not observed by
Worker; retain actual client/provider transfer receipts separately.

## Interpreting a run

Join queue attempts by session, immutable original, client operation, placement
and verification-operation commitments. A delivery commitment hashes the real
queue message ID; an attempt commitment changes on redelivery. Pair start and
finish events before calculating overlap, using same-isolate object/provider
counts without a deployment-wide concurrency claim. Across isolates, retain
the actual clock uncertainty before comparing intervals.

Storage reads also occur for isolated qualification. Their `storage_read`
scope becomes production workload evidence only when correlated with actual
`production_queue` originals. Retained replay emits no fresh read event.
Missing finishes after process termination remain unknown. Missing/truncated
logs prevent an observation-completeness claim.

To audit zero Native bulk, correlate every positive typed control exchange with
the actual Native ingress byte logs and the matching direct provider transfer
and Worker source-read receipts. Do not substitute a zero-valued fixture
counter, isolated qualification report, or an absent event for measured traffic.
