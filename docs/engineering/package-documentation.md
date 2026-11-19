# Package documentation

Package reference documentation is generated from the same module declarations
that define a package's options and abilities, published as an authenticated
Nix store object beside the package, and read by every surface (APM, the `aos`
CLI, Hub, and editors) through one shared reader. No surface keeps its own
copy of package option or ability semantics, and no reader evaluates Nix.

How to read documentation is covered in the user guides:
[configuration](../users/aos/configuration.md),
[ability inspection](../users/aos/ability-inspection.md), the Hub
[web interface](../users/aos-hub/web.md), [API](../users/aos-hub/api.md#read-native-release-documentation),
and [CLI](../users/aos-hub/cli.md#read-published-native-documentation).

## Generation

`nativeArtifactsFor` in `pkgs/default.nix` evaluates the package's modules with
`evalPackageModules` (`lib/packages/evaluate.nix`) in a package-only scope and
takes the resulting `documentation` value. It writes the JSON to a store object
`<package>-documentation` whose root is a directory containing `options.json`,
exposed as the package's `documentationArtifact`. The document has the schema
`aos.module.documentation`:

```json
{"schema":"aos.module.documentation","scope":["package","example"],"system":"x86_64-linux","packages":[],"options":[],"abilities":{}}
```

Descriptions, defaults, and examples have one declaration site: the ordinary
option and ability declarations in the package module. There is no separate
documentation map that could override or supplement them. The document
retains string context only for the authenticated module source locations it
cites, so it does not pull the package payload into its closure.

Documentation is a separate store object from the runtime output, so editing
prose produces a new documentation object without rebuilding the payload or
changing its runtime identity.

## Publication

A package's signed platform entry (`aos-registry-format`,
`PlatformEntry::module_documentation`) carries a `NativeArtifactMeta` locator:

| Field | Meaning |
|---|---|
| `store_path` | Immutable documentation directory root |
| `nar_hash`, `nar_size` | Identity of the directory's uncompressed NAR |
| `references` | Sorted direct references as 32-character store hashes |
| `document_sha256`, `document_size` | Identity of the exact `options.json` bytes |

The signed Git release authenticates the association between
package, version, platform, and documentation identity. The NAR and narinfo are
published through the ordinary binary-cache path with the rest of the release,
so documentation is retained and collected with its release like any other
artifact.

## Hub indexing and reads

Hub never generates documentation. During release admission, the shared indexer
(`aos-hub-service/src/indexer/native_documentation.rs`) runs identically on the
native server and the Cloudflare Worker:

1. Validate the signed locator before opening anything.
2. Fetch the narinfo with a size bound and require that its store path, NAR
   size and hash, and references equal the locator, that `Compression` is
   `none`, and that the NAR URL is a safe relative `nar/*.nar` path.
3. Fetch the NAR with a bound of the signed size (at most 32 MiB) and decode it
   with the strict reader in `aos-module-docs/src/nar.rs`, which rejects extra
   nodes and trailing data. A single document is at most 12 MiB.
4. Check the exact `options.json` bytes against `document_sha256` and
   `document_size`, then parse them with the shared runtime document reader.

Requiring uncompressed NARs keeps the Worker free of decompression code while
staying within the standard Nix cache protocol.

Search uses disposable SQL projections (`aos-hub-db/src/db/native_documentation.rs`):
rows of package, option, and operation entries generated from the verified
document and pinned to the exact release, commit, and document digest.
Deleting them and re-indexing the signed registry reproduces the same corpus.
Detail pages and API reads re-verify the signed directory and `options.json`
bytes on every read rather than trusting the projection.

## Readers

`aos-module-docs` is the shared reader. Its `runtime` module validates
evaluator-generated documents and desired transactions, renders them to text,
JSON, and HTML, compares two package versions, and derives search documents.
Renderers escape all text and own all markup; documents carry no executable
content.

| Surface | Implementation |
|---|---|
| `apm docs search`, `show`, `schema`, `man`, `serve` | `aos-package-manager/src/documentation/`, over installed packages or a Hub |
| `apm docs lsp`, `aos language-server` | `aos-package-manager/src/documentation_lsp/`: completion, hover, diagnostics, and schema over LSP stdio; buffers are never evaluated |
| `aos hub docs` | Hub documentation RPCs from the CLI |
| `aos docs runtime` | Local rendering of a documentation or transaction file |
| Hub browse pages and Connect API | `aos-hub-service` web and documentation services |

Installed-package documentation works offline. An APM profile records each
package's signed `module_documentation` locator with the package, so upgrade
and rollback switch code and documentation together, and remote reads verify
the same identities before using the shared reader.

`aos doc` (`aos-nix-docs`) is a separate developer browser for repository Nix
library functions and the Nix language. It reads `##` comments from a source
checkout and never reconstructs package or option reference data.
