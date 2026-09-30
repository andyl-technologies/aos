# Generated documentation and inspection

`lib.evalPackageModules` projects `aos.module.documentation` from the evaluated
options and native operations. It includes package identities, input/result
types and descriptions, source ownership, handler availability, and configured
effect names. Recipes publish it as `documentationArtifact/options.json`.
There is no independently maintained documentation catalog.

`aos docs runtime` renders that reference or an `aos.package.transaction` as
text, JSON, or standalone HTML. Hub's `/-/runtime-abilities` viewer and
`/-/api/runtime-documentation` API use the same reader. Package links show who
declares, handles, and configures an operation; graph views show ordered execution
and dependency links. Uploaded documents are not retained or executed.

These views describe evaluated configuration, not observed runtime state or
publication authenticity. Disabled conditional uses cannot be inferred from
absent definitions. Existing release indexes, installed-package docs, and live
inspection consumers remain to be migrated to the native artifacts.

See the [target state](13-target-state.md) and the
[end-to-end code examples](../../users/aos/runtime-abilities.md).
