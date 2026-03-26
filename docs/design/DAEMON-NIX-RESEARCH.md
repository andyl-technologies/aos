# Nix Derivation Instantiation and Store Internals

Research document for the `aos daemon` architecture. Covers the complete lifecycle
of Nix derivations: evaluation, instantiation, dependency graph computation,
building, binary cache interaction, and store path management.

---

## 1. nix-instantiate: Turning .nix into .drv Files

`nix-instantiate` evaluates Nix expressions and produces store derivation (`.drv`)
files in the Nix store, **without building anything**.

### Usage

```bash
# Default: evaluate ./default.nix, produce .drv paths on stdout
nix-instantiate

# Evaluate a specific file or attribute
nix-instantiate path/to/file.nix
nix-instantiate -A pkgs.hello default.nix

# Evaluate an expression directly
nix-instantiate --expr 'derivation { name = "foo"; builder = "/bin/sh"; system = "x86_64-linux"; }'

# Evaluation-only modes (no .drv written to store)
nix-instantiate --eval --expr '1 + 2'           # => 3
nix-instantiate --eval --strict --json -E '...'  # Force full evaluation, JSON output
nix-instantiate --parse -E '...'                 # Just parse, print AST
```

### Key Flags

| Flag | Effect |
|------|--------|
| `--eval` | Evaluate and print result (derivations hashed but NOT written to store) |
| `--strict` | Recursively evaluate all attributes/list elements |
| `--json` | Output JSON representation |
| `--xml` | Output XML representation |
| `--raw` | Print string results without escaping |
| `--parse` | Only parse, print abstract syntax tree |
| `--read-write-mode` | Allow evaluation in read/write mode (needed for IFD) |
| `-A attr` | Select a specific attribute from the top-level set |
| `--arg name value` | Pass a Nix expression as a function argument |
| `--argstr name value` | Pass a string argument |

### How It Works

1. Parse the `.nix` file(s) into an AST
2. Evaluate the expression (lazy by default, strict with `--strict`)
3. For each derivation encountered:
   - Compute the ATerm representation
   - Hash it to determine the `.drv` store path
   - Compute output paths (which depend on the `.drv` hash)
   - Write the `.drv` file to the Nix store
4. Print the `.drv` store paths to stdout

The key insight is that **output paths are known before building**. Nix can
compute `/nix/store/<hash>-<name>` for all outputs at evaluation time, enabling
the entire dependency graph to be resolved purely from `.drv` files.

### Modern Alternative: `nix derivation show`

```bash
# Show derivation in JSON format (more parseable than raw ATerm)
nix derivation show /nix/store/...-hello.drv
nix derivation show nixpkgs#hello
```

---

## 2. The .drv File Format (ATerm)

Store derivations are serialized in the ATerm (Annotated Term) format. This is
a legacy format but remains the canonical on-disk representation.

### ATerm Structure

```
Derive(
  <outputs>,
  <inputDrvs>,
  <inputSrcs>,
  <platform>,
  <builder>,
  <args>,
  <env>
)
```

The field order is fixed and positional.

### Field Definitions

#### outputs: `[(<name>, <path>, <hashAlgo>, <hash>), ...]`
List of output tuples. Each tuple has:
- `name`: output name (e.g. "out", "dev", "lib")
- `path`: the computed store path for this output (empty for content-addressed)
- `hashAlgo`: hash algorithm (empty for input-addressed; "sha256" for FODs)
- `hash`: expected hash (empty for input-addressed; the declared hash for FODs)

Example (input-addressed, single output):
```
[("out","/nix/store/abc...-hello","","")]
```

Example (fixed-output derivation):
```
[("out","/nix/store/xyz...-source.tar.gz","sha256","0123456789abcdef...")]
```

#### inputDrvs: `[(<drvPath>, [<outputName>, ...]), ...]`
List of (derivation path, requested outputs) pairs. Each entry says "I depend
on these specific outputs of this derivation."

```
[("/nix/store/...-bash.drv",["out"]),
 ("/nix/store/...-gcc.drv",["out","lib"])]
```

#### inputSrcs: `[<storePath>, ...]`
List of store paths that are direct source inputs (not derivation outputs).
These are typically source files added to the store via `builtins.path`,
`builtins.toFile`, or similar.

```
["/nix/store/...-builder.sh","/nix/store/...-source"]
```

#### platform: `<string>`
The system type, e.g. `"x86_64-linux"`, `"aarch64-linux"`.

#### builder: `<string>`
Absolute path to the executable that performs the build.
Typically `/nix/store/...-bash-5.2/bin/bash`.

#### args: `[<string>, ...]`
Command-line arguments passed to the builder.
Typically `["-e","/nix/store/...-builder.sh"]`.

#### env: `[(<key>, <value>), ...]`
List of (name, value) pairs for environment variables. Almost all attributes
passed to `builtins.derivation` end up here. Includes the computed output paths
(e.g. `out=/nix/store/...`).

### Concrete Example (Raw ATerm)

```
Derive(
  [("out","/nix/store/dsgf85...-hello","","")],
  [("/nix/store/l54djr...-bash-4.4-p23.drv",["out"])],
  [],
  "x86_64-linux",
  "/nix/store/qdp56f...-bash-4.4-p23/bin/bash",
  ["-c","echo \"Hello World!\" > $out\n"],
  [("builder","/nix/store/qdp56f...-bash-4.4-p23/bin/bash"),
   ("name","hello"),
   ("out","/nix/store/dsgf85...-hello"),
   ("system","x86_64-linux")]
)
```

### JSON Representation (via `nix derivation show`)

```json
{
  "/nix/store/hbsv13...-hello.drv": {
    "outputs": {
      "out": {
        "path": "/nix/store/dsgf85...-hello"
      }
    },
    "inputSrcs": [],
    "inputDrvs": {
      "/nix/store/l54djr...-bash-4.4-p23.drv": ["out"]
    },
    "platform": "x86_64-linux",
    "builder": "/nix/store/qdp56f...-bash-4.4-p23/bin/bash",
    "args": ["-c", "echo \"Hello World!\" > $out\n"],
    "env": {
      "builder": "/nix/store/qdp56f...-bash-4.4-p23/bin/bash",
      "name": "hello",
      "out": "/nix/store/dsgf85...-hello",
      "system": "x86_64-linux"
    }
  }
}
```

### Format Variants

- `Derive(...)` -- stable derivations (standard)
- `DrvWithVersion("xp-dyn-drv", ...)` -- experimental dynamic derivations

### Parsing Libraries

- **Haskell**: `nix-derivation` package on Hackage
- **Rust**: `nix_compat::derivation` in Tvix
- **Go**: `go-nix` library
- **Python**: `python-nix` or manual parsing

---

## 3. Computing the Full Dependency Graph from .drv Files

### Algorithm

Given a set of `.drv` files, the full dependency graph is computed by
recursively walking `inputDrvs`:

```
function computeClosure(drvPath):
    drv = parseDrv(drvPath)
    deps = {}
    for (inputDrvPath, outputNames) in drv.inputDrvs:
        deps.add(inputDrvPath, outputNames)
        deps.union(computeClosure(inputDrvPath))
    return deps
```

### Using nix-store --query

```bash
# Get the full closure (all recursive dependencies) of a .drv
nix-store --query --requisites /nix/store/...-hello.drv

# Get just immediate dependencies
nix-store --query --references /nix/store/...-hello.drv

# Get outputs of a derivation
nix-store --query --outputs /nix/store/...-hello.drv

# Print as a tree
nix-store --query --tree /nix/store/...-hello.drv

# Export as graphviz dot format
nix-store --query --graph /nix/store/...-hello.drv

# Export as GraphML
nix-store --query --graphml /nix/store/...-hello.drv
```

### Programmatic Approach

For the daemon, parsing `.drv` files directly is more efficient:

1. **Instantiate** all top-level derivations with `nix-instantiate`
2. **Parse** each `.drv` file (ATerm or JSON via `nix derivation show`)
3. **Walk** `inputDrvs` recursively to build the DAG
4. **Topologically sort** the DAG for build ordering
5. For each node, check if its outputs already exist (see section 4)

### Key Properties

- The dependency graph is a **DAG** (directed acyclic graph)
- `inputDrvs` edges are labeled with output names (a drv may depend on only
  some outputs of another drv)
- `inputSrcs` are leaf nodes (source files, not derivation outputs)
- Fixed-output derivations are "content-addressed roots" -- their output paths
  depend only on the declared hash, not their build inputs

---

## 4. nix-store --query: Checking What's Built/Available

### Checking if a Path Exists

```bash
# Check if specific paths are valid (exist in store)
nix-store --check-validity /nix/store/...-hello
nix-store --check-validity --print-invalid /nix/store/...-hello

# Check if a store path is valid (returns 0 or 1)
nix-store --query --hash /nix/store/...-hello  # fails if invalid
```

### Querying Path Metadata

```bash
# Get the deriver (.drv) that built a path
nix-store --query --deriver /nix/store/...-hello

# Get all valid derivers of a path
nix-store --query --valid-derivers /nix/store/...-hello

# Get the NAR hash of a path
nix-store --query --hash /nix/store/...-hello

# Get the NAR size
nix-store --query --size /nix/store/...-hello

# Get immediate runtime references
nix-store --query --references /nix/store/...-hello

# Get reverse references (what depends on this path)
nix-store --query --referrers /nix/store/...-hello

# Get GC roots pointing to a path
nix-store --query --roots /nix/store/...-hello

# Get a specific env var from a .drv
nix-store --query --binding out /nix/store/...-hello.drv
```

### Querying Substitutability

```bash
# Check what's missing and what can be substituted
nix-store --query --missing /nix/store/...-hello.drv  # (via newer nix CLI)

# Using the newer CLI:
nix path-info --json /nix/store/...-hello
nix path-info --closure-size /nix/store/...-hello
```

### Building / Realising

```bash
# Build a derivation (realizes it)
nix-store --realise /nix/store/...-hello.drv

# Dry run (just report what would be built/substituted)
nix-store --realise --dry-run /nix/store/...-hello.drv

# Repair a path by redownloading from substituter
nix-store --repair-path /nix/store/...-hello
```

### Programmatic Validity Check

The `isValidPath` function in the Nix store API:
1. Checks the in-memory cache (`pathInfoCache`)
2. Checks the on-disk NAR info cache (`diskCache`)
3. Falls back to `isValidPathUncached` (queries the SQLite DB for local store)

For a daemon that wants to skip builds, the key check is:
**For each output in the .drv, does that output path already exist as a valid
store path?**

---

## 5. Fixed-Output Derivations (FODs)

### What They Are

Fixed-output derivations are a special class of derivation where the output
hash is declared in advance. This is the mechanism behind `fetchurl`,
`fetchgit`, and all other Nix fetchers.

### Key Properties

- **Network access**: FODs are the ONLY derivation type allowed network access
  during build. The Nix sandbox grants network access specifically for FODs.
- **Content-addressed**: The output store path depends only on the declared hash,
  not on the build inputs or builder script.
- **Hash verification**: After the build completes, Nix computes the actual hash
  of the output and compares it to the declared hash. Mismatch = build failure.
- **Idempotent caching**: If a path with the right hash already exists in the
  store, the FOD is never rebuilt (regardless of how it was produced).

### .drv Representation

A FOD's output tuple includes the hash algorithm and expected hash:

```
[("out", "/nix/store/xyz...-source.tar.gz", "sha256", "0123456789abcdef...")]
```

The env vars include:
- `outputHash = "sha256-..."` or `"0123456789abcdef..."` (hex)
- `outputHashAlgo = "sha256"`
- `outputHashMode = "flat"` or `"recursive"`

### Hash Modes

- **flat**: Hash the raw file bytes (`sha256sum`-compatible). Used by `fetchurl`
  for tarballs (hashing the `.tar.gz` itself, not its contents).
- **recursive** (aka NAR): Hash the NAR serialization of the output. Used by
  `fetchgit`, `fetchFromGitHub`, etc. where the output is a directory tree.

### Output Path Computation for FODs

```
fingerprint = "fixed:out:<hashMode>:<hashAlgo>:<hash>:"
innerHash = SHA256(fingerprint)
storePath = "/nix/store/" + nixBase32(compress(SHA256("output:out:sha256:" + hex(innerHash) + ":/nix/store:" + name))) + "-" + name
```

The crucial point: **changing the builder script or fetcher URL does NOT change
the output path** as long as the declared hash stays the same.

### Practical Usage

```nix
# AOS fetchurl pattern
src = fetchurl {
  urls = [ "https://example.com/foo-1.0.tar.gz" ];
  hash = "sha256-abc123...=";
};
```

Nix computes the output path from the hash alone. If that path exists (locally
or in a binary cache), the download is skipped entirely.

---

## 6. Importing Paths into the Nix Store

### nix-store --import / --export

The export/import format is a streaming protocol that bundles NAR data with
metadata (references, deriver).

**Export format** (per path, from `export-import.cc`):

```
<uint64: 1>                    # "there is another path" marker
<NAR data>                     # complete NAR serialization of the path
<uint32: 0x4558494e>           # magic number: exportMagic ("NIXE" in ASCII)
<string: store path>           # e.g. "/nix/store/abc...-hello"
<string[]: references>         # list of reference store paths
<string: deriver>              # deriver .drv path (or "" if unknown)
<uint64: 0>                    # legacy signature marker (0 = no signature)
```

The stream ends with `<uint64: 0>` (no more paths).

**Usage:**

```bash
# Export a closure
nix-store --export $(nix-store -qR /nix/store/...-hello) > closure.nar

# Import on another machine
nix-store --import < closure.nar
```

**Limitations:**
- Non-extensible format
- Metadata comes AFTER the NAR, so import must buffer the entire NAR in memory
- No signature verification (import with `NoCheckSigs`)

### nix-store --add-fixed

Add a file directly to the store as a content-addressed path:

```bash
# Add as flat hash
nix-store --add-fixed sha256 myfile.tar.gz

# Add as recursive (NAR) hash
nix-store --add-fixed --recursive sha256 mydir/
```

This computes `source:sha256:<NARhash>:/nix/store:<name>` and adds the path.
No derivation is involved.

### nix-store --add

Simple content-addressed add (always recursive/NAR, SHA256):

```bash
nix-store --add myfile
```

### nix-store --dump / --restore

Low-level NAR operations (no metadata):

```bash
# Dump a path as NAR to stdout
nix-store --dump /nix/store/...-hello > hello.nar

# Restore a NAR to a local path
nix-store --restore /tmp/hello < hello.nar
```

---

## 7. nix-store --register-validity

Registers paths in the Nix store's SQLite database as valid, **without copying
any data** (the files must already exist at the store path). This is used
internally by Nix and by tools like `closureInfo` in nixpkgs.

### Text Format

The format is line-oriented, read by `decodeValidPathInfo()` in `store-api.cc`:

```
<store path>                                    # /nix/store/abc...-hello
<NAR hash (hex, SHA256)>                        # (only with --hash-given)
<NAR size>                                      # (only with --hash-given)
<deriver path or empty line>                    # /nix/store/...-hello.drv or ""
<number of references>                          # e.g. 2
<reference 1>                                   # /nix/store/...-glibc-2.35
<reference 2>                                   # /nix/store/...-hello (self-ref)
```

Repeated for each path. EOF terminates.

### Variants

```bash
# Register with auto-computed hashes (Nix hashes the path contents itself)
nix-store --register-validity < registration

# Register with pre-computed hashes (format includes hash+size lines)
nix-store --register-validity --hash-given < registration

# Allow re-registration of existing paths
nix-store --register-validity --reregister < registration

# Load database (like --register-validity --reregister --hash-given)
nix-store --load-db < registration

# Dump database (inverse: writes registration format to stdout)
nix-store --dump-db
nix-store --dump-db /nix/store/...-hello
```

### Example (with --hash-given)

```
/nix/store/abc123...-hello
a1b2c3d4e5f6...  (64-char hex SHA256 of NAR)
205920
/nix/store/r6h5b3...-hello.drv
2
/nix/store/6yaj6n...-glibc-2.27
/nix/store/abc123...-hello
```

### Without --hash-given

```
/nix/store/abc123...-hello

0
```

(Nix computes the hash by NARing the path itself.)

---

## 8. Binary Cache Protocol

### Overview

A Nix binary cache is an HTTP server (or S3 bucket, or local directory) that
serves pre-built store paths. The protocol is simple: `nix-cache-info` for
metadata, `.narinfo` files for path metadata, and `.nar` files for content.

### nix-cache-info

Served at the root of the cache:

```
StoreDir: /nix/store
WantMassQuery: 1
Priority: 40
```

- `StoreDir`: Must match the client's store dir (usually `/nix/store`)
- `WantMassQuery`: `1` = client may batch-query many paths at once
- `Priority`: Lower = preferred when multiple caches are configured

### .narinfo Files

Lookup: `GET /{hash}.narinfo` where `{hash}` is the 32-character Nix base32
hash from the store path (the part before the `-name`).

Example: for `/nix/store/gdh8165b7rg4y53v64chjys7mbbw89f9-hello-2.10`,
request `GET /gdh8165b7rg4y53v64chjys7mbbw89f9.narinfo`.

**Format** (key-value, newline-separated):

```
StorePath: /nix/store/gdh8165b7rg4y53v64chjys7mbbw89f9-hello-2.10
URL: nar/1iq8bqv1fnvxn9w41gfkjpndzlmhi3my8rcmfhp0gh7fh4vcp30s.nar.xz
Compression: xz
FileHash: sha256:1iq8bqv1fnvxn9w41gfkjpndzlmhi3my8rcmfhp0gh7fh4vcp30s
FileSize: 41272
NarHash: sha256:0mkfk4iad66xkld3b7x34n9kxri9lrpkgk8m17p97alacx54h5c7
NarSize: 205920
References: 6yaj6n8l925xxfbcd65gzqx3dz7idrnn-glibc-2.27 gdh8165b7rg4y53v64chjys7mbbw89f9-hello-2.10
Deriver: r6h5b3wy0kwx38rn6s6qmmfq0svcnf86-hello-2.10.drv
Sig: cache.nixos.org-1:EmAANryZ1FFHGmz5P...
```

**Field definitions:**

| Field | Required | Description |
|-------|----------|-------------|
| `StorePath` | Yes | Full store path |
| `URL` | Yes | Relative path to the NAR file |
| `Compression` | Yes | `none`, `xz`, `bzip2`, `gzip`, `zstd` |
| `FileHash` | No | Hash of the compressed NAR file (`sha256:...` in Nix base32) |
| `FileSize` | No | Size of the compressed NAR file in bytes |
| `NarHash` | Yes | Hash of the uncompressed NAR (`sha256:...` in Nix base32) |
| `NarSize` | Yes | Size of the uncompressed NAR in bytes |
| `References` | Yes | Space-separated store path basenames (no `/nix/store/` prefix) |
| `Deriver` | No | Basename of the `.drv` file |
| `Sig` | No | Signatures (`keyname:base64sig`, space-separated for multiple) |
| `CA` | No | Content address (e.g. `fixed:sha256:...` for FODs) |

### NAR Storage

NAR files are stored at paths like `nar/<hash>.nar.<compression>`. The hash
in the URL is typically the `FileHash` (content-addressed NAR storage), making
NARs deduplicated across different store paths that happen to have the same content.

### Signing

Signatures use Ed25519. The signed data is a **fingerprint** string:

```
1;/nix/store/<path>;sha256:<narhash_base32>;<narsize>;<sorted references>
```

The signature format in `.narinfo` is `keyname:base64(ed25519_sign(fingerprint))`.

### HTTP Protocol Summary

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/nix-cache-info` | GET | Cache metadata |
| `/<hash>.narinfo` | GET | Path metadata + NAR location |
| `/nar/<hash>.nar[.xz]` | GET | Compressed NAR content |
| `/<hash>.narinfo` | PUT | Upload path metadata (for pushing) |
| `/nar/<hash>.nar[.xz]` | PUT | Upload NAR content (for pushing) |

---

## 9. Manual Substitution (Without the Nix Daemon)

To manually substitute a path from a binary cache:

### Step-by-Step

1. **Compute the hash part** of the target store path:
   ```
   /nix/store/gdh8165b7rg4y53v64chjys7mbbw89f9-hello-2.10
                ^-- this 32-char part
   ```

2. **Fetch the .narinfo**:
   ```bash
   curl https://cache.nixos.org/gdh8165b7rg4y53v64chjys7mbbw89f9.narinfo
   ```

3. **Parse the narinfo** to get `URL`, `NarHash`, `NarSize`, `Compression`, `References`, `Sig`

4. **Verify the signature** (optional but recommended):
   - Compute fingerprint: `1;<StorePath>;<NarHash>;<NarSize>;<References>`
   - Verify Ed25519 signature against the public key

5. **Download the NAR**:
   ```bash
   curl -o path.nar.xz https://cache.nixos.org/nar/1iq8bqv...nar.xz
   ```

6. **Decompress** the NAR (if compressed):
   ```bash
   xz -d path.nar.xz
   ```

7. **Verify the NAR hash**:
   ```bash
   nix-hash --type sha256 --flat path.nar
   # Must match NarHash from narinfo
   ```

8. **Restore the NAR** to the store path:
   ```bash
   nix-store --restore /nix/store/gdh8165b7rg4y53v64chjys7mbbw89f9-hello-2.10 < path.nar
   ```

9. **Register the path** as valid:
   ```bash
   printf '/nix/store/gdh8165b7rg4y53v64chjys7mbbw89f9-hello-2.10\n<narhash-hex>\n<narsize>\n<deriver-or-empty>\n<num-refs>\n<ref1>\n<ref2>\n' \
     | nix-store --register-validity --reregister --hash-given
   ```

### Important Notes

- References must already be valid in the store before registering the new path
- This means you must process the closure in topological order (dependencies first)
- The daemon normally handles all of this automatically during substitution

---

## 10. Store Path Computation and Derivation Output Hashes

### Store Path Format

All store paths follow: `/nix/store/<hash>-<name>` where `<hash>` is 32
characters of Nix base32.

### Nix Base32

Nix uses a **non-standard** base32 encoding:
- Character set: `0123456789abcdfghijklmnpqrsvwxyz` (note: no `e`, `o`, `t`, `u`)
- Encoding processes bytes **in reverse** order
- This is NOT RFC 4648 base32

### Hash Compression

Before base32 encoding, the 32-byte SHA256 hash is XOR-compressed to 20 bytes:

```
compressed[i % 20] ^= hash[i]   for i in 0..31
```

This yields 20 bytes, which encode to exactly 32 base32 characters.

### Store Path Computation: Input-Addressed (Normal) Derivations

For a regular derivation output:

1. **Prepare the .drv for hashing**: Take the ATerm representation and:
   - Clear all output paths (set to "")
   - Clear the corresponding `env` entries for outputs
   - Replace each `inputDrv` with the hash of that input `.drv` file
     (this is the "modulo" operation that breaks hash cycles)

2. **Hash the modified .drv**: `innerHash = SHA256(modifiedATermString)`

3. **Build fingerprint**: `"output:<outputName>:sha256:<hex(innerHash)>:/nix/store:<name>"`

4. **Compute store path**: `SHA256(fingerprint)` -> compress to 20 bytes -> Nix base32

Example fingerprint:
```
output:out:sha256:0fb43a8f107d1e986cc3b98d603cf227ffa034b103ff26118edf5627387343fc:/nix/store:hello
```

### Store Path Computation: Fixed-Output (Content-Addressed) Derivations

For FODs, the output path depends ONLY on the declared hash:

1. **Build inner fingerprint**: `"fixed:out:<hashAlgo>:<hex(declaredHash)>:"`
   (for flat mode) or `"fixed:out:r:<hashAlgo>:<hex(declaredHash)>:"` (for
   recursive/NAR mode)

2. **Hash**: `innerHash = SHA256(innerFingerprint)`

3. **Build outer fingerprint**: `"output:out:sha256:<hex(innerHash)>:/nix/store:<name>"`

4. **Compute store path**: same as above (compress + base32)

### Store Path Computation: Source Paths

For source files added via `builtins.path` or `builtins.toFile`:

1. **NAR-hash the content**: `contentHash = SHA256(NAR(content))`
2. **Build fingerprint**: `"source:sha256:<hex(contentHash)>:/nix/store:<name>"`
3. **Compute store path**: compress + base32

### .drv File Path Computation

The `.drv` file itself is content-addressed using the "text" method:

1. **Hash the ATerm content**: `contentHash = SHA256(aTermContent)`
2. **Build fingerprint**: `"text:sha256:<hex(contentHash)>:/nix/store:<name>.drv"`
   (with references to inputSrcs and inputDrvs appended)
3. **Compute store path**: compress + base32

### Key Insight: Why Input-Addressed Paths Change

For input-addressed derivations, ANY change to ANY input (even a comment in a
build script) changes the `.drv` hash, which changes the fingerprint, which
changes the output path. This is why binary caches are essential -- even trivial
rebuilds produce different store paths.

For FODs, the output path is stable as long as the declared hash doesn't change.
This is what makes source tarballs cacheable across different nixpkgs versions.

---

## Summary: Implications for the aos Daemon

### Key Operations the Daemon Needs

1. **Instantiate**: Run `nix-instantiate` to turn `.nix` expressions into `.drv` files
2. **Parse .drv**: Read ATerm or use `nix derivation show --json` to get structured data
3. **Build dependency graph**: Walk `inputDrvs` recursively from target `.drv` files
4. **Check availability**: For each output path, check if it's valid locally or in a cache
5. **Schedule builds**: Topologically sort the DAG, build leaves first
6. **Fetch from cache**: Download `.narinfo`, then `.nar`, decompress, restore, register
7. **Import results**: After remote builds, import paths via NAR + register-validity

### Store Interaction Primitives

| Operation | Command | Daemon Equivalent |
|-----------|---------|-------------------|
| Instantiate | `nix-instantiate` | Parse + eval Nix |
| Check valid | `nix-store --check-validity` | `isValidPath()` |
| Query refs | `nix-store -q --references` | `queryPathInfo().references` |
| Build | `nix-store --realise` | `buildPaths()` |
| Fetch NAR | `curl + nix-store --restore` | HTTP GET + NAR unpack |
| Register | `nix-store --register-validity` | `registerValidPaths()` |
| Add FOD | `nix-store --add-fixed` | `addToStoreSlow()` |
| Export | `nix-store --export` | `exportPaths()` |
| Import | `nix-store --import` | `importPaths()` |

### References

- [Nix Pills #18: Store Paths](https://nixos.org/guides/nix-pills/18-nix-store-paths)
- [Nix ATerm Format](https://nix.dev/manual/nix/2.33/protocols/derivation-aterm)
- [Store Derivation and Deriving Path](https://nix.dev/manual/nix/2.32/store/derivation/)
- [NAR Format](https://nix.dev/manual/nix/2.24/protocols/nix-archive)
- [Binary Cache Specification](https://fzakaria.com/2021/08/12/a-nix-binary-cache-specification)
- [What's in a Nix Store Path](https://fzakaria.com/2025/03/28/what-s-in-a-nix-store-path)
- [Nix Derivations by Hand](https://bernsteinbear.com/blog/nix-by-hand/)
- [nix-instantiate Manual](https://nix.dev/manual/nix/2.33/command-ref/nix-instantiate)
- [nix-store --query Manual](https://nix.dev/manual/nix/2.32/command-ref/nix-store/query)
- [Nix Source: store-api.cc](https://github.com/NixOS/nix/blob/master/src/libstore/store-api.cc)
- [Nix Source: export-import.cc](https://github.com/NixOS/nix/blob/master/src/libstore/export-import.cc)
- [Nix Source: nix-store.cc](https://github.com/NixOS/nix/blob/master/src/nix/nix-store/nix-store.cc)
- [Tvix nix_compat::narinfo](https://docs.tvix.dev/rust/nix_compat/narinfo/index.html)
