# Reference — Error mapping

This document is the normative table of outcomes, the protocol status code
each produces, the structured error detail attached, whether a client may
retry, and the POSIX `errno` a surface returns to a caller when the outcome
reaches a filesystem operation. It is cited by
[`18-protocol.md`](../18-protocol.md) (PROTO-45, PROTO-47) and
[`20-consistency.md`](../20-consistency.md) (CONS-24 through CONS-27).

Status codes are the Connect and gRPC codes. Error details are protobuf
messages defined in [`protocol.md`](protocol.md) §Error details and carried
in the status details. Where the `errno` column says "n/a" the outcome cannot
reach a POSIX operation.

## Outcomes

| Outcome | Status code | Detail | Retry | `errno` |
| --- | --- | --- | --- | --- |
| Success | `OK` | | | 0 |
| Malformed request, limit exceeded (hash count, frame size) | `INVALID_ARGUMENT` | `Limit` | no | `EINVAL` |
| Unknown enum value in an acted-on field | `INVALID_ARGUMENT` | | no | `EINVAL` |
| Token missing, expired, malformed, or signature invalid | `UNAUTHENTICATED` | | no, after refresh | `EACCES` |
| Grant does not cover the operation | `PERMISSION_DENIED` | | no | `EACCES` |
| Content not held, or not permitted to know | `NOT_FOUND` | | no | `ENOENT` |
| Ref does not exist, or not permitted to know | `NOT_FOUND` | | no | `ENOENT` |
| Pack already held (idempotent upload) | `ALREADY_EXISTS` | `PackAck` | no; success | 0 |
| CAS precondition mismatch | `FAILED_PRECONDITION` | `RefState` | after re-read | `EBUSY` |
| Commit references packs no tier can locate | `FAILED_PRECONDITION` | `MissingPacks` | after upload | `EIO` |
| Hop limit reached | `FAILED_PRECONDITION` | `HopLimit` | no | `ELOOP` |
| Writer epoch stale (fenced) | `FAILED_PRECONDITION` | `RefState` with `fenced=true` | no | `EROFS` |
| Lease expired | `FAILED_PRECONDITION` | `RefState` with `fenced=true` | no | `EROFS` |
| Unresolvable merge conflict under `writers=many` | `ABORTED` | `Conflict` | no | `EBUSY` |
| Auto-rebase attempts exhausted | `ABORTED` | `Conflict` | later | `EBUSY` |
| Reflog truncated past resume point | `OUT_OF_RANGE` | | after re-read | n/a |
| Range beyond pack end | `OUT_OF_RANGE` | | no | `EIO` |
| Root quota exceeded at commit | `RESOURCE_EXHAUSTED` | `Quota` | no | `ENOSPC` |
| Host reservation exhausted at write | n/a (local) | | no | `EDQUOT` |
| Exposure torn down (worker aborted, lease ended, drained for upgrade) | n/a (local) | | no; remount | `ENOTCONN` |
| Lock request on a read-only exposure | n/a (local) | | no | `ENOLCK` |
| Admission budget spent (warm, peer serve) | `RESOURCE_EXHAUSTED` | `Budget` | with `retry-after` | n/a |
| Pack larger than advertised limit | `RESOURCE_EXHAUSTED` | `Limit` | no | `EFBIG` |
| Home authority unreachable | `UNAVAILABLE` | `Home` | yes | `EIO` |
| Freshness bound unsatisfiable | `UNAVAILABLE` | `Staleness` | yes | `EIO` |
| Backend lacks conditional writes in multi-writer mode | `FAILED_PRECONDITION` | `BackendProbe` | no | n/a |
| Transient backend or transport failure | `UNAVAILABLE` | | yes | `EIO` |
| Deadline exceeded | `DEADLINE_EXCEEDED` | | yes | `EIO` |
| Cancelled by caller | `CANCELLED` | | | `EINTR` |
| Chunk failed verification on admit | n/a (local) | | refetch from another candidate | `EIO` if no candidate remains |
| Unsupported pack or tree encoding version | `UNIMPLEMENTED` | `Versions` | no | `EIO` |
| Method not implemented | `UNIMPLEMENTED` | | no | `ENOSYS` |
| Internal error | `INTERNAL` | | no | `EIO` |

## Rules

- A surface MUST return the `errno` in the table for the first outcome that
  applies and MUST NOT translate an outcome to an `errno` the table does
  not list for it.
- `NOT_FOUND` MUST be returned for both "absent" and "not permitted to know"
  and the response MUST be indistinguishable in message, detail, and timing
  per PROTO-46. A caller with `admin` on the enclosing root MAY receive
  `PERMISSION_DENIED` instead when the object exists.
- An error whose Retry column says "yes" MUST carry `retryable=true` in its
  `ErrorInfo` detail; every other error MUST carry `retryable=false`. A
  client MUST NOT retry an error marked `false`.
- `retry-after`, when present, is a duration in the error detail and MUST
  be respected as a minimum backoff.
- `EROFS` from fencing is permanent for the exposure per CONS-19. Every
  write and `fsync` on a fenced exposure MUST return `EROFS`.
- `fsync` failures are sticky per CONS-24: the same `errno` MUST be
  returned by later `fsync` calls on that file until a commit including the
  file succeeds.
- `EDQUOT` is produced locally by the host tier's reservation logic and
  never crosses the protocol. `ENOSPC` is produced by a commit failing a
  root quota and reaches the caller only through `fsync` in `sync` mode or
  through the control directory.
- In `sync` mode, an `fsync` that fails because of `UNAVAILABLE`,
  `DEADLINE_EXCEEDED`, `INTERNAL`, or a verification failure with no
  remaining candidate MUST return `EIO`, and the protocol status and detail
  MUST be retained in `.terrane/status` until the next successful commit.

## `errno` summary

| `errno` | Produced by |
| --- | --- |
| `EACCES` | authentication or authorization failure |
| `ENOENT` | absent or undisclosed content or ref |
| `EINVAL` | malformed request |
| `EBUSY` | CAS mismatch, unresolved conflict, rebase exhaustion |
| `EROFS` | fenced or expired exposure |
| `ENOSPC` | root quota exceeded at commit |
| `EDQUOT` | host reservation exhausted |
| `EFBIG` | pack exceeds limit |
| `ELOOP` | hop limit |
| `EINTR` | cancelled |
| `ENOSYS` | method unimplemented |
| `EIO` | every other failure to read, upload, or commit |
