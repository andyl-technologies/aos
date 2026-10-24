# Compiler invocation evidence

Builds selecting `retainActionGraph` preserve the executed action log and
expanded aquery commands. The response-file expansion must match the executed
command and its declared response-file digest, including when one target has
separate execution and target configurations.

These builds also retain `evidence/compiler-inputs.json`. For every successful
`Rustc` action, it records the exact wrapper argument vector's digest and each
indirect argument, environment, or workspace-status input. Shared file records
preserve UTF-8 contents, byte lengths, and SHA-256 digests. Every file must appear
in that action's executed input inventory with the same digest. Missing files,
changed contents, ambiguous commands, failed compiler actions, and conflicting
contents for a shared path fail the build.

Local disk-cache hits normally leave intermediate outputs unmaterialized. The
evidence launcher option materializes all action outputs so these inputs can be
read before the private build tree is removed. It preserves disabled remote
cache/executor endpoints, offline repository setup, and sandbox policy. Ordinary
builds retain their default materialization behavior. Virtual `FileWrite` inputs
come from aquery's declared contents and undergo the same execution-digest check.

The CLI library proof in `../tests/evidence/cli-compiler-input-retention.json`
uses the frozen lint-qualified CLI workspace. It qualifies byte retention for
that source snapshot; it does not qualify a later CLI source revision or expand
the wrapper's file syntax, substitutions, or compiler defaults. Semantic option,
native ABI, linker closure, and runtime comparisons remain independent gates.

The retained helper can also check an existing build while its execution root
is still available:

```text
python3 tools/bazel/tests/retain_compiler_inputs.py \
  --build BUILD_OUTPUT --execution-root PRIVATE_BASE/execroot/_main \
  --output compiler-inputs.json
```
