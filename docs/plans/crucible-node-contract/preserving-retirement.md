# Preserving runtime retirement

The retirement implementation in `486bbfb5f9` retains the CPU, Clock, Script and
Block transfer domain while source shutdown, native supervision and durable
placement are outstanding. Terminal request metadata does not release native
capacity. Failed or uncertain retirement retains the original ownership and
history for reconciliation.

The common runtime separates retirement transfer from authenticated release.
Release requires the same original activation, completed owner shutdown and
transfer, and installed supervisor qualification. The default qualification
refuses release. A copied receipt or observed process exit does not supply
continuation or replay authority.

The daemon reserves lifetime request credit before preparing an ordinary or
preserving world. Its original ledger bounds unique requests at 4,096, including
retained records and tombstones. Capacity refusals use a separate data-only
mailbox; they do not construct a native catalog or start a worker. Ordinary and
fallback refusal reconciliation share eight attempts per turn. This is an
attempt bound: synchronous storage callbacks may still block.

The gem5 provider retains original completion and acknowledgment history through
shutdown and transfer. The host retains its original COW state and pending input
associations. Failed durable placement keeps the same completion and reservation
instead of permitting another dispatch.

## Verification

The reviewed functional predecessor passed eight focused capacity and ownership
controls. Earlier 27 retirement controls and seven capacity controls belong to
their separately retained source revisions; they are not additional executions
of the final source. The integration adds a shared retirement-record type and
equivalent conditional expression, plus two test naming/comment corrections.

The integrated retirement source passed all 37 quality checks and strict
all-target checks for the core, provider, daemon and CLI. The scanner executables
were verified to use the actual worktree. An earlier cache hit used a different
source root and is excluded from these results.

The required hermetic `rust.aos-test-targets` gate passed in 1,396.29 seconds.
Its output audit verified 167 compiled test targets, including 69 integration
targets across 48 packages; all 244 workspace compiler artifacts were freshly
built. Selected source contents and executable modes matched the frozen source,
and source/output NAR identities matched registration. This gate compiles tests;
it does not execute them. The application package excludes the separately
packaged daemon and CLI, which received the strict checks above.

These results apply to the retirement source preceding the subsequent Packet
integration. They do not qualify native source removal, two fresh ordinary
daemon/CLI restores, device parity, or complete backend acceptance. Those remain
separate behavioral gates. Raw build logs and state evidence remain local.
