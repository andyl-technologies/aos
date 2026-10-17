# Upstream cleanup validator custody

The response-loss listener and replay validator each invoke the selected Native
ignored helper in `authenticate_lost_reply` phase. This phase validates an already
retained upstream response and current read-only metadata. It is a separate
process from the Native service and from dispatch/replay/settle transport calls.
Its reading of a retained physical response is never Native transport consumption.

Each invocation now uses the owned `Popen` child and the published runtime's
`helper_process` custody checks before waiting for exit. Actual PID/start/UID,
executable hash and private raw command/environment files are retained. Missing
or changed identity, timeout or a failed child cannot satisfy completed-response
authentication. Only that exact child is stopped on its own failed capture.

`authentication-invocation.private.json` has these closed fields:

```text
version scope phase transportScope nativeTransportObservation helperProcess
arguments input output outputErrorKind started finished stdout stderr exitCode
failureKind completeProcessCustody listenerSourceSha256 runtimeSourceSha256
```

Scope is `managed_cleanup_upstream_authentication_helper`, phase is
`authenticate_lost_reply`, transportScope is `read_only_upstream_validation`, and
nativeTransportObservation is always null. `helperProcess` is null or the actual
runtime pin with its private command/environment references. `started` and
`finished` carry observed `unixNs` and `monotonicNs` decimal strings. Input,
optional output, stdout and stderr references retain their actual path/hash/size.
`completeProcessCustody` describes custody, not successful authentication; a
nonzero exit still has a real lifetime. Missing/invalid output stays null or has
outputErrorKind and cannot become a positive proof.

The returned authentication receipt includes `invocation` (the private hashed
JSON reference) and `helperProcess` (that invocation value), alongside its existing
raw request/signature/reply and Rust proof references. The Rust result must still
match the exact original/profile/request and unchanged SQL, and physicalReply must
be present. Any nativeExchangeObservations value in this upstream-only result
refuses. The global inventory must account for both auxiliary lifetimes alongside
all service and transport-helper callers without borrowing their process pins.

The focused tests launch actual separate source-built Python children, pin their
identity, retain their raw files/output, and cover executable mismatch and nonzero
exit. They do not execute Rust authentication, SQL, provider calls, response loss,
or final selected-tuple qualification. Existing physical authentication and loss
ordering remain unchanged.

## Deterministic pre-input startup

The read-only authenticator child receives `AOS_MANAGED_CLEANUP_STARTUP_ROOT`
and a fresh lower-hex 128-bit `AOS_MANAGED_CLEANUP_STARTUP_NONCE`. The ignored
Native helper optionally pauses before reading its business input, opening the
database or authenticating a physical reply. It atomically publishes an
owner-private readiness file with closed `{version,nonce,pid,scope}` fields;
scope is `managed_cleanup_before_input`. The listener compares the actual child
PID and nonce, captures the live executable/argv/environment lifetime, then
atomically publishes closed `{version,nonce}` release. Both sides refuse an
absent or changed handshake and enforce a ten-second startup bound. Production
service and provider paths receive no handshake or new authority.

This avoids assuming the child remains alive while its large ELF is hashed.
No exited-process pin or Native service identity substitutes for the actual
child. A release acknowledges observer custody only; physical MAC, reply
correlation and current SQL checks still run unchanged afterward.

Each actual stdout and stderr pipe retains at most 65,536 bytes. Bounded
collection uses the selected child's actual pipes and a thirty-second wall
ceiling. On overflow or timeout, only that owned child is killed, retained
prefixes remain incomplete, and positivity refuses. An unexpected inherited
open pipe is unknown. The result does not assert that retained prefixes equal
all bytes written by a child after overflow.

Invocation adds `startupReady`, `startupRelease`, `outputBound`,
`outputOverflow` (`stdout`/`stderr` booleans), and `completeOutputCollection`.
These fields establish metadata custody only, never Native transport bytes.
The actual short-lived source tests complete immediately after release without
post-work sleeps, cover missing handshake and wrong executable refusal, and
prove bounded overflow retention. They do not execute Rust authentication,
SQL or provider operations. The Native entry still requires its affected
compile/registration gate from this same frozen source before acceptance.
