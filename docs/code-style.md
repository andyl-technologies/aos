# Code style

AOS uses the established style of each language. `rustfmt` formats Rust and
Alejandra formats Nix. Generated, vendored, and upstream source keeps its
existing style.

## Rust

Public APIs use standard traits and names. Conversions implement `From` or
`TryFrom` when those contracts fit. An `as_` method returns a cheap borrowed
view, `to_` creates a new value, and `into_` consumes `self`. Collections expose
the usual `iter`, `iter_mut`, and `into_iter` methods. `Display` provides the
user-facing representation; `Debug` provides the diagnostic one.

A newtype fits when same-representation values could be swapped accidentally or
construction must validate them. An enum makes a mode readable where a boolean
would produce `run(task, true)`. A parameter struct or builder replaces a long
list of optional arguments. Functions borrow values used only during the call
and take ownership when they retain or consume them. Invariant-bearing types
keep fields private and validate them in constructors.

`?` and early returns keep edge cases from enclosing the operation. `match`
fits exhaustive alternatives; `if let` fits a single relevant pattern.
Iterator chains fit uniform transformations. A loop reads more clearly once
the body carries mutable state, branches several ways, or performs effects
between steps.

Public library APIs return typed errors. A wrapping error retains its source
and adds the failed operation or subject, such as a manifest name or path;
converting the source to a formatted string discards that chain. Production
code contains no `.unwrap()` or `.expect()`. Tests and examples may panic when
the panic is the assertion.

AOS uses `unsafe` only for a specific requirement that safe Rust cannot
reasonably meet. Each unsafe block has a preceding `// SAFETY:` explanation of
the invariants that make it sound.

Blank lines separate multi-statement setup, validation, external effects, and
result construction. Extracting a helper can remove a nested branch,
consolidate repeated logic, or give a multi-step operation a name at its call
site. A forwarding wrapper has a role when it enforces policy, stabilizes an
interface, or creates a test seam.

AOS has no hard function-length limit. Around 100 logical lines prompts a look
for mixed abstraction levels, growing state, or deep nesting; an ordered
protocol or state machine may still read best as one function. A hand-written
file approaching 1,000 lines prompts the same review at module scale. Beyond
roughly 1,500 lines, the interface and module documentation explain its
cohesion. Co-located `#[cfg(test)]` code counts separately.

Comments record safety arguments, ordering, atomicity, wire compatibility,
security policy, and the reason behind a surprising choice. They sit next to
the code that relies on the constraint. AOS has no comment-density target.

Every crate root and module starts with a `//!` overview. Public items have
`///` documentation; `Result`, panic, and unsafe contracts use `# Errors`,
`# Panics`, and `# Safety`. Fenced blocks carry a language tag. Comments on
Clap fields stay concise because they also become command-line help.

Test names state the condition and expected result. Table-driven failures name
the case, and golden data includes its regeneration and review procedure.

## Nix

Within `modules/`, AOS follows the Dendritic pattern: each auto-discovered file
owns one feature's option declarations, configuration, and checks. Its path
names the feature, such as `services/registry-hub.nix`, rather than a layer such
as `options.nix` or `config.nix`. Files under `systems/` compose features and
describe variant-specific choices. `modules/default.nix` remains the discovery
point, and `_`-prefixed paths hold deliberately imported implementation details.

Package expressions under `pkgs/` are the `callPackage`-style exception. A
package file builds one package from explicit dependencies; modules consume
packages and attach system policy.

Package and helper functions name their dependencies in the argument set.
Module functions retain `...` for arguments supplied by the module system.
`let` introduces derived values; `rec` remains for genuine sibling references.
Qualified names such as `lib.mkIf` preserve provenance that a broad `with`
scope hides. `inherit (source) name` identifies the source explicitly.

Complex interpolations get a named binding before an embedded shell string.
Generated JSON uses `builtins.toJSON` rather than hand-written escaping.
Attribute-set updates with `//` are shallow, so nested configuration uses
module merging or an explicit recursive update when intended. URLs are quoted
strings, and repository expressions do not depend on impure `<...>` lookup
paths.

Package files read in a stable order: arguments, version and source,
dependencies, phases, outputs, and metadata. The hermetic package rules
determine every tool and library. Reusable builders and substantial checks
receive names and files of their own.

Around 1,000 hand-written lines prompts a review for a separable feature,
builder, or test family. Beyond roughly 1,500 lines, the change explains why
one file remains easier to navigate. Generated code and declarative inventories
follow their natural size.

Short package phases read naturally inline. Repeated sequences, independently
testable stages, and dense multi-language escaping favor a named script or
helper; around 150 lines is a review point rather than a limit. Embedded shell
uses the derivation's shell syntax and AOS-built tools. Paragraph breaks
separate setup, execution, validation, and publication. Comments identify
intentional non-zero exits, cleanup ownership, and unusual sandbox assumptions.


## References

The language conventions track the
[Rust Style Guide](https://doc.rust-lang.org/style-guide/),
[Rust API Guidelines](https://rust-lang.github.io/api-guidelines/),
[nix.dev best practices](https://nix.dev/guides/best-practices.html), and the
[Dendritic pattern](https://github.com/mightyiam/dendritic).
