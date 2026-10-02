# Nix authoring and contracts

Operations are nested module configurations at
`aos.abilities.<ability>.operations.<operation>`. `input`, `result`, and `handler`
are deferred module values. Definitions from different files merge normally;
`effects.<name>.input` is checked against the merged input module.

A domain manager can reuse the input module under `aos.services.<name>` or another
ordinary domain option, add `enable`, and derive effects from the final config.
No schema copy, empty instance declaration, external operation constructor, or
manual declaration/configuration split is required. The reusable operation
`module` and typed `outputs` are derived read-only values.

Recipes expose `module` and `moduleDeps`; deployment-time modules receive explicit
payload artifacts and ordinary `lib`, `config`, and `options` arguments.
Descriptions live beside option declarations and generate the reference.

See the [target state](13-target-state.md) and the
[end-to-end code examples](../../users/aos/runtime-abilities.md).
