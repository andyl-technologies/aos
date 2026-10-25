# Accache Rust execution profiles

The standalone accache qualification uses separate release and editor execution
profiles. Its Cargo release builds compile procedural macros at optimization 0,
with assertions and overflow checks disabled. The workspace's `strip = true`
also reaches those tools. The Cargo editor oracle explicitly supplies its
optimization-3 target flags globally, so editor macros receive those flags too.
First-party target compilation keeps its existing optimization-3 settings.

```text
nix-build tools/bazel/tests/accache.nix -A execution-profiles --no-out-link
nix-build tools/bazel/tests/accache.nix -A all --no-out-link
```

The [profile report](../tests/evidence/accache-execution-profiles.json) retains
four native Cargo macro compilation requests and the authenticated Bazel
compiler inputs for both macros and both first-party targets. All eight checked
Bazel compiler actions execute in Linux sandboxes without cache hits. The check
compares optimization, debug information, assertion/overflow settings, and
stripping. Compiler capability queries are excluded from compilation records;
duplicate or missing actual macro compilations fail the check.

Cargo traces retain requested arguments. The independent native Cargo profile
probe exercises default overflow behavior when Cargo omits the compiler flag.
These observations do not establish complete compiler, executable-chain,
native ABI, or linker equivalence.

The shared family helper accepts `editorExecRustcFlags` separately from
`execRustcFlags`. Equal settings reuse the ordinary workspace. Different
settings preserve the target graph while compiling the editor's native macros
with their selected profile. Other families retain their existing defaults
until separately enrolled. Optional compiler tracing captures Cargo test
compilations and the editor's compiler entry point, which remains observable
when rust-analyzer replaces `RUSTC_WRAPPER`.

The qualified editor derivation selects this independent workspace. The generic
development launcher still selects the ordinary workspace; development editor
routing requires separate enrollment. Full tests, diagnostics, installation,
cache integration, performance, and production cutover retain their own gates.
Accache remains daemonless and uses local disk storage.
