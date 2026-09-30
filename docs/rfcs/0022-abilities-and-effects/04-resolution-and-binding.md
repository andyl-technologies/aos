# Module resolution and handler selection

Package resolution selects an exact module closure and payload artifacts before
evaluation. `moduleDeps` supplies explicit module dependencies. Conflicting
versions or source identities for the same package in a scope are rejected.

Handler selection is ordinary Nix module configuration under the operation's
`handler`. It is not a separately authored provider map or runtime discovery
loop. The generated graph retains the exact selected implementation and typed
dependencies. An enabled effect without a handler fails before host mutation.
Unused interfaces and reference-only evaluation need no selected handler.

APR authenticates exact deployment and documentation companions in release
metadata. APM resolves the selected module closure and admits its retained
artifacts before execution. Module-only dependencies remain available for
offline reconfiguration without installing their payloads. The generic evaluator
does not infer authorization from an import, store path, or declaration.

See the [target state](13-target-state.md) and the
[end-to-end code examples](../../users/aos/runtime-abilities.md).
