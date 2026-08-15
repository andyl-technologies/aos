# Patch 0065 — `crucible-authenticated-terminal-lifecycle`

## Purpose

Makes terminal process exit a dedicated, authenticated, idempotent QAPI
operation. Ordinary VM resume is never overloaded and cannot authorize exit.

## Command contract

`crucible-complete-terminal-lifecycle` accepts exactly:

| Field | Contract |
| --- | --- |
| `action-sha256` | 64 lowercase hexadecimal characters naming the resolved action emitted by the pending lifecycle event |
| `evidence-sha256` | 64 lowercase hexadecimal characters naming the exact `CRUCLIF1` evidence bytes |
| `process-generation` | Nonzero host-supervised generation of the exact owned QEMU child |

QEMU compares both digests with the single pending terminal decision. The first
matching request binds the generation and schedules the transition-specific
process exit. An identical retry succeeds without scheduling another exit. A
different generation or digest, malformed digest, absent decision, unsupported
build, or second decision fails without resuming the VM.

The command does not call or share behavior with QMP `cont`. Its success reply
means only that the exact exit has been authorized; the host must still reap the
owned child and verify status `70`, `71`, or `72` before committing supervision.

## State and recovery

Patch 0059 serializes the pending decision, both digests, authorization state,
and bound process generation. Restoring an unauthorized decision permits the
same command. Restoring an authorized decision preserves idempotence and never
permits guest execution. The host transaction journal independently records the
request and observed child status.

## Live gates

1. Reject uppercase, short, long, non-hexadecimal, wrong-action, wrong-evidence,
   zero-generation, and wrong-generation requests.
2. Repeat an identical request before shutdown dispatch and prove one shutdown
   request and no guest instruction retirement.
3. Lose the first response, retry, reap the child, and prove the expected status.
4. Issue ordinary `cont` while a terminal decision is pending and prove it has
   ordinary resume semantics only; the host policy must not expose that path
   during a terminal transaction.
5. Save and restore before and after authorization and prove the same closed
   outcomes.

## Licensing checklist

The QAPI schema, dispatcher, and lifecycle state are QEMU/GPL-side changes. The
Apache host sends only the documented versioned process command and does not
link QEMU code or headers. The signed patch, bundle, corresponding source, and
license-boundary gates ship together.
