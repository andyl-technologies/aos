# Patch 0114: authenticate fault-result payloads

Patch `0133-crucible-authenticate-fault-result-payloads.patch` binds every
queued fault-result header to the exact payload retained beside it.

## Problem

Successful typed node handlers populated their result evidence hash while
encoding evidence. A handler that rejected during preparation could still
publish a typed rejection payload, but the common dispatcher queued that
payload with a stale hash. The transport authenticated its copied bytes, while
the host correctly rejected the inconsistent typed header as incomplete
adapter state instead of classifying the authored rejection.

## Contract

The single queue-ownership boundary computes SHA-256 after choosing the exact
owned payload, including the canonical empty payload. That boundary overwrites
any handler-local digest before publishing the result. Success, rejection,
deferred completion, capability queries, and malformed-command results
therefore share one payload-identity rule.

The live hardware negative control submits a typed clock-source transition to
a source that does not advertise read-error capability. QEMU must return one
authenticated rejection, the production host must classify it as rejected,
and the next boundary must remain usable.

## Compatibility

The result header and payload formats do not change. Results that already
contained the correct digest retain the same bytes; previously inconsistent
rejection headers now carry the digest required by the existing ABI contract.
