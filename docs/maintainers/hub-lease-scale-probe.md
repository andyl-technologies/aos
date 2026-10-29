# Local lease-scale acquisition probe

The `do-e2e` Worker exposes `POST /__hub/lease-scale-acquire` for the
prospective local policy in [hub-lease-scale-observations.md](hub-lease-scale-observations.md).
The ordinary Worker returns 404 for this path. The probe acquires an existing
configured cohort through the production renewal helper. Issuance can commit
issuer metadata; the probe does not admit provider work, create an object, or
return a lease token. Its successful response is measurement metadata, not a
provider dispatch grant or qualification artifact.

## Configured custody

Use the existing protected `HUB_STORAGE_WORK_KEY`, separately from the issuer
renewal key and physical guard keys. Requests and replies have distinct local
scale MAC domains. Install `HUB_LEASE_SCALE_FIXTURE` as a closed JSON object:

```json
{"version":1,"run_id":"<32 lowercase hex>","isolate_label":"<32 lowercase hex>","installations":[]}
```

The abbreviated example requires the actual operator-installed issuer
installations. Each must match a configured authority and executor. The existing
`HUB_EXTERNAL_OBJECT_CONSUMER` must pass its normal validation, have exactly 32
distinct cohorts, and retain its 128 KiB bound. The probe additionally requires
the selected 2-second executor uncertainty and either the 8-second or 120-second
maximum lifetime. These values are prospective local test inputs; they do not
establish clock qualification or change production policy.

The configuration commitment is SHA-256 of the Rust canonical JSON serialization
of `[object_consumer, fixture_configuration]`. Preserve the exported Rust field
order and lossless integer strings when constructing it. The Worker recomputes
the commitment from its actual parsed configuration; a caller-provided digest
cannot select a different installation, prefix, profile, or cohort.

## Bounded originals and results

The request is canonical JSON, at most 4 KiB, with no URL query:

```text
{version, run_id, nonce, source_digest, configuration_digest,
 cohort_digest, issued_at, expires_at}
```

The nonce is 64 lowercase hexadecimal characters. The original request lasts
at most 30 seconds and uses an exclusive conservative expiry. After the actual
renewal wait and before returning metadata, the Worker rechecks that original
window and verifies the returned token against the exact configured cohort,
prefix, timing profile, issuer key and current clock. A temporary verification
floor is never persisted or passed to an effect executor. The reply contains
only the original commitments, process label, token digest, lease sequence and
observed timing. It contains no token, credential, provider bytes or signature
seed.

The acquisition uses the existing 32-cohort and 32-follower coordination bounds
and origin-local polling. Failure or cancellation of the owner retains its
unavailable entry until the immutable original expiry. Neither a probe timeout
nor stopping a process establishes remote issuance drain or provider settlement.
The unchanged 5-second refresh margin can make an 8-second token ineligible for
warm reuse. Record actual misses and RPCs rather than tuning that margin.

## Genuine scale setup and runtime joins

Use a fresh actual authority, namespace and dedicated issuer store for each
incompatible lifetime profile. For each case, create and validate 16 real private
bindings, admit their 16 exact associations and current credential members
through normal root Plan/Apply controls, then export each association through
the actual bootstrap executable into a separate new private output directory.
All 16 canonical `publication.json` files must be byte-identical to the final
current SQL authority head. Retain both exported read/write cohorts for each
association. Do not replace missing exports with generated cohorts, truncate a
publication, or initialize a used journal.

Launch four fresh workerd processes with separate physical stores and retain
their actual PID/start-time, module hashes, embedded source digest and full
configuration commitments. Labels in the reply are only joins to those
independent process receipts. Use the actual issuer recorder and privately
captured original requests and signed replies to count physical RPCs, sequences,
acknowledged commits, signing CPU/wall samples, errors and latency. Join the
recorder's healthy footer to its actual successful terminal process outcome.
Missing samples remain absent.

The controlled source tests prove request/custody rejection and configuration
shape only. Four-process/32-cohort scale, renewal ratios, jitter, issuer budgets,
whole-isolate memory, fleet behavior and Hosted observations remain unmeasured
until the matching reviewed runtime tuple completes the actual workload.
