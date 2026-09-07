# Downstream link fixture

This separate consumer crate checks the final consumer's runtime search path
rather than relying on linker arguments emitted for the adapter's own tests.
Build through the AOS dev
environment and execute the resulting binary directly with `LD_LIBRARY_PATH`
unset. It shares the workspace lockfile to keep dependency versions identical.
The executable retains a reference to the production runner, so its
dynamic dependency closure includes the installed AOS FUSE transport.

```text
nix develop -c cargo build --manifest-path crates/aos-filesystem-fuse/tests/fixtures/link-consumer/Cargo.toml
```

The adapter's build script supplies a runtime search path for its own test
targets only. A separately packaged consumer must declare `aos-fuse-transport` in its AOS
`runtimeDeps`; the dev shell supplies the equivalent target linker flags for
incremental builds. No FUSE connection is opened by this fixture. On non-Linux
targets its entry point is empty because this transport profile is Linux-only.
