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

`aos ability check-compat BEFORE AFTER --owner PACKAGE` (or `--os`) checks
release compatibility against generated public input/result schemas
from the previous and current owner release. Package interfaces follow the
owning package version; OS/base interfaces follow the OS release version.
Removed operations or fields, new required inputs, and type changes are breaking
changes or require review. Optional input additions and new operations are
allowed. Opaque constraints require explicit review, and structural comparison
does not prove runtime behavior. Breaking changes are permitted outside the
previous release's captured compatibility range, or with an exception identifying
the exact diagnostic and explaining why it is permitted. A new release's policy
cannot relax previous obligations. Package recipe shorthand supplies the captured
requirement; OS versions remain exact declarations with default caret policy. The check consumes the generated reference rather than a separately
maintained interface manifest. `--exceptions FILE` supplies exact diagnostic
IDs with explanatory reasons; incompatible reports are emitted before a nonzero
exit.

See the [target state](13-target-state.md) and the
[end-to-end code examples](../../users/aos/runtime-abilities.md).
