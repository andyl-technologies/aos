# Recursive handler composition

A handler selects either a terminal `program` artifact or a set of `children`
and `exports`. A child imports another operation's read-only `module` and supplies
its input configuration. The selected lower handler is evaluated recursively.

`types.deferred T` accepts a concrete value or a compatible result reference.
Referencing `children.<name>.outputs.<result>` adds a dependency; exporting that
value forwards the typed child result. Rust resolves it only after execution.
The parent composition does not launch a redundant process. Invalid references,
cycles, or incompatible exports fail graph construction or validation.

This supports richer interfaces implemented through several cooperating OS
primitives without reducing all implementations to the smallest feature set.

See the [target state](13-target-state.md) and the
[end-to-end code examples](../../users/aos/runtime-abilities.md).
