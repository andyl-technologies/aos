# Module resolution and handler selection

Package resolution selects an exact module closure and payload artifacts before
evaluation. `moduleDeps` supplies explicit module dependencies. Conflicting
versions or source identities for the same package in a scope are rejected.

Handler selection is ordinary Nix module configuration under the operation's
`handler`. It is not a separately authored provider map or runtime discovery
loop. The generated graph retains the exact selected implementation and typed
dependencies. An enabled effect without a handler fails before host mutation.
Unused interfaces and reference-only evaluation need no selected handler.

The publishing/installing consumer supplies authenticated release resolution and
artifact admission. The generic evaluator does not infer authorization from an
import, store path, or declaration. Production registry integration is a remaining
consumer migration.

See the [target state](13-target-state.md) and the
[end-to-end code examples](../../users/aos/runtime-abilities.md).
