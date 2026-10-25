# Build-script compiler profiles

`checks.build.bazel.build-script-profiles` checks the metadata that Cargo-style
build scripts receive from the source-built Bazel rules. Run it independently:

```sh
nix-build -A checks.build.bazel.build-script-profiles --no-out-link
```

The pinned rules previously derived `OPT_LEVEL` and `DEBUG` from Bazel's
compilation mode. Workspace flags can override that mode independently for
target libraries and execution tools. The AOS patch reads those role-specific
flags so a library compiled at `s` receives `OPT_LEVEL=s`, while its execution
dependencies compiled at `0` receive `OPT_LEVEL=0`.

`mkAosBazelWorkspace.cargoProfile` explicitly selects `debug` or `release` for
the root build. This identity also reaches execution tools: an unoptimized
release build dependency still receives `PROFILE=release`. Null retains the
compilation-mode fallback for families awaiting root-profile qualification.
CLI tests select `debug`, and the production CLI suite selects `release`.

The qualification executes native debug, release, editor, and Wasm builds in
fresh private output bases without compiler caches. Each builds a library and
a native procedural macro. A build script forwards its observed profile into
generated compiler environment files, whose executed input digests are checked
before comparison with the actual compiler flags. The pinned libm dependency
independently checks that `optimizations_enabled` follows its optimization
level. The Wasm target keeps generators, procedural macros, and their libm
dependency native.

This gate qualifies these declared global profiles and generated inputs.
Complete external compiler, native C, linker, runtime, and other-family parity
remain separate acceptance checks.
