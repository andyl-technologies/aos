# Selected-source Managed cleanup helper

`_hub-managed-cleanup-native-helper.nix` returns an auxiliary derivation when
passed `{ pkgs = (import commonSource {}).pkgs; }`. `commonSource` must be the
same final independently accepted immutable source selected for ordinary
Native, do-e2e Worker and reviewer artifacts. Evaluating a derivation is not an
installed artifact or runtime qualification.

The recipe reuses `pkgs.aos-hub.src`, the existing fixed vendor contract, AOS
Rust/Cargo and the ordinary package's native libraries, protobuf and console
inputs. It builds only the Native library test target:

```text
cargo test --release --frozen --offline --no-run -p aos-hub --lib \
  --features postgres,required-live-dialects -j$NIX_BUILD_CORES
```

The existing Cargo builder also requests JSON compiler messages. Installation
selects exactly one `aos_hub` library test executable from those messages and
checks its exact ignored registration with `--list --ignored --exact`. It does
not invoke the ignored test or dispatch any SDK, SQL mutation or runtime
fixture. The recipe does not change ordinary Native/default test features or
the nine fields in `_hub-hybrid-runtime.nix`.

## Outputs and selected tuple

The auxiliary output has:

```text
bin/aos-hub-managed-cleanup-contract
nix-support/ignored-test-registration.txt
```

The ordinary fixup/strip/closure checks remain enabled. No pre-fixup hash is
presented as the final executable identity. After realization, the tuple
coordinator reads the actual installed ELF and refuses a zero-size executable
or one exceeding 512 MiB before it enters the reviewed private provenance.
The recipe supports native Linux evaluation only. It exposes its exact selector,
Cargo command, native filtered source and do-e2e Worker filtered source through
`passthru`, without putting build-only source references into its runtime files.

Fleet includes the actual output in the selected VM closure. Its called
adapter receives `managedCleanupNativeHelper` pointing to the installed ELF
and `managedCleanupNativeHelperProvenance` pointing to a private independently
reviewed record with exactly five fields:

```json
{
  "version": 1,
  "commonSourceStorePath": "<actual selected immutable common source>",
  "workerFilteredSourceStorePath": "<actual selected do-e2e Worker filtered source>",
  "testExecutableSha256": "<actual installed executable SHA256>",
  "testExecutableBytes": "<canonical decimal, 1 through 536870912>"
}
```

The selected tuple binds the actual derivation/recipe and those source paths.
The adapter must reread the installed ELF and compare its exact hash and size
before use. It must also check source-path equality against the selected final
tuple and retain the private original input and resulting receipt. No caller
PASS flag, historical executable, configured size or matching name fills a
missing artifact/source observation.

The only selected registration is:

```text
storage_work::oci_cleanup::controlled::actual_managed_terminal_cleanup_pair
```

Actual invocation uses that exact ignored test with an owner-private
`AOS_MANAGED_CLEANUP_CONTROLLED_INPUT` file. Its currently accepted phase
contract, existing current SQL and separate genuine Delete capability determine
whether observation or a cleanup exchange is permitted. Later accepted phase
changes must be compiled from the same final common source; this recipe does
not infer them from an older ELF. OCI-only acceptance never becomes Delete
permission. Real transport/SDK/cold replay and normal SQL recovery remain
independent runtime acceptance requirements.
