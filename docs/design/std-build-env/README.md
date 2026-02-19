# Standard Build Environments

## Problem

AOS packages are built hermetically in the Nix sandbox, which has no network
access. This works fine for C/C++ packages (all deps are other AOS packages
passed as inputs), but languages with their own package managers need special
handling:

- **Rust**: `cargo build` downloads crates from crates.io at build time.
- **Go**: `go build` downloads modules from proxy.golang.org at build time.
- **Python**: `pip install` downloads wheels from PyPI at build time.

Today, Go packages work only because their source tarballs happen to include
vendored dependencies. Rust packages (like nginx-acme) fail outright. There
is no principled mechanism for fetching language-specific dependencies.

Beyond dependency fetching, each package manually writes its own phases —
duplicating boilerplate for common build patterns and omitting standard
post-build steps that both [Guix](https://guix.gnu.org/manual/en/html_node/Build-Systems.html)
and [nixpkgs](https://ryantm.github.io/nixpkgs/stdenv/stdenv/) provide:
testing, binary fixup, shebang patching, debug symbol handling, and runtime
path validation.

## Design Goals

1. **Hermetic** — all network access happens in hash-verified fixed-output
   derivations (FODs). The actual package build has no network access.
2. **Correct by default** — build envs include check, fixup, and validation
   phases. Packages are tested and stripped unless explicitly opted out.
3. **Explicit** — no magic. Package authors see exactly what deps are fetched
   and how the build runs.
4. **Composable** — build environments compose with mkDerivation, not replace
   it. A Rust package that shells out to cmake for C deps just works.
5. **Minimal** — add only the abstractions that earn their keep. Don't
   over-engineer for hypothetical build systems.

## Architecture

Three layers, each independently useful:

```
Layer 3:  Build Environment Functions     mkCargoPackage, mkGoPackage
              (convenience wrappers around mkDerivation)
                            |
Layer 2:  Phase Generators                cargoPhases, goPhases
              (functions returning phase lists, parameterized by deps)
                            |
Layer 1:  Dependency Fetchers             fetchCargoDeps, fetchGoModules
              (FODs that download language deps with hash verification)
```

Underpinning all three layers is a **standard fixup phase** that runs after
install, providing binary patching, stripping, shebang rewriting, and runpath
validation — regardless of which build system produced the output.

Packages can use any layer directly. Layer 3 is the most convenient (like
nixpkgs' `buildRustPackage`). Layer 1 is the most flexible (fetch deps, then
use custom phases).

---

## Standard Phases

Every build environment produces a phase list following this canonical order.
Languages customize the middle (configure/build/check/install) but share the
bookends (unpack, patch, fixup):

```
unpack → patch → configure → build → check → install → fixup → installCheck
```

### Phase Descriptions

| Phase | Purpose | Default |
|-------|---------|---------|
| **unpack** | Extract source archive, enter source dir | Shared across all build envs |
| **patch** | Apply patches, run postPatch | Only if `patches` is non-empty |
| **configure** | Language-specific setup (cargo vendor config, go env, ./configure) | Per build env |
| **build** | Compile (cargo build, go build, make, ninja) | Per build env |
| **check** | Run test suite against build tree | Per build env; controlled by `doCheck` |
| **install** | Copy artifacts to `$out` | Per build env |
| **fixup** | Strip, patch shebangs, patch ELF, validate runpath | Shared across all build envs |
| **installCheck** | Test against installed `$out` (smoke tests) | Optional; controlled by `doInstallCheck` |

### Check Phase

Each build environment defines a language-appropriate check phase:

| Build Env | Check Command | Parameters |
|-----------|--------------|------------|
| cargo | `cargo test --release --frozen --offline` | `cargoTestFlags`, `checkType` |
| go | `go test -v ./...` | `goTestFlags`, `tags` |
| autoconf | `make check` | `checkTarget`, `checkFlags` |
| cmake | `ctest --output-on-failure` | `checkTarget` |
| meson | `meson test -C build` | `mesonTestFlags` |

The check phase is **enabled by default** (`doCheck = true`). Packages that
have known test failures or tests requiring network/hardware can disable it:

```nix
mkCargoPackage {
  # ...
  doCheck = false;  # tests require network access
}
```

Test-specific parameters allow running tests with different configurations
than the build:

```nix
mkCargoPackage {
  # ...
  # Build in release mode, test in debug mode (faster compilation)
  buildType = "release";
  checkType = "debug";

  # Only test specific crates in a workspace
  cargoTestFlags = "--workspace --exclude integration-tests";

  # Disable parallel tests if tests share state
  doParallelCheck = false;
}
```

### Fixup Phase

The fixup phase runs after install for **all** build environments. It
performs standard post-processing on the `$out` tree:

#### Strip Debug Symbols

Removes debug symbols from ELF binaries and libraries to reduce closure
size. Uses `strip -S` (debug symbols only) for libraries, `strip -s`
(all symbols) for executables.

```nix
mkCargoPackage {
  # ...
  dontStrip = true;         # disable stripping entirely
  # OR
  separateDebugInfo = true;  # extract to $debug output instead of removing
}
```

When `separateDebugInfo = true`, debug info is extracted into a separate
`debug` output (`$debug/lib/debug/.build-id/XX/YYYY...`), accessible by
debuggers via build-id lookup. This keeps the main output small while
preserving debuggability.

#### Patch ELF Binaries

Uses `patchelf` to clean up RPATH entries in ELF binaries:

- Removes references to build-only paths (build tools, temporary dirs)
- Shrinks RPATH to only the entries actually needed at runtime
- Ensures the dynamic linker path is correct

```nix
mkDerivation {
  # ...
  dontPatchELF = true;  # disable (e.g., for binaries with intentional RPATHs)
}
```

#### Patch Shebangs

Rewrites `#!/usr/bin/env python3` and similar shebangs to absolute Nix
store paths found in `PATH`. This ensures scripts work without relying on
`/usr/bin/env` or system-installed interpreters.

```nix
mkDerivation {
  # ...
  dontPatchShebangs = true;  # disable (e.g., for packages that generate scripts)
}
```

#### Validate Runpath

Checks that all ELF binaries in `$out` can find their required shared
libraries. Fails the build if a binary references a library that isn't in
its RPATH or the standard search path. This catches missing `runtimeDeps`
early rather than at runtime.

```nix
mkDerivation {
  # ...
  dontValidateRunpath = true;  # disable (e.g., for dlopen-only deps)
}
```

#### Move Docs

Relocates `man/`, `doc/`, `info/` directories under `share/` to follow the
FHS convention. Controlled by `dontMoveDocs`.

### InstallCheck Phase

Runs after fixup, testing the **installed** package rather than the build
tree. This catches install-time issues (wrong RPATHs, missing files,
broken scripts). Disabled by default (`doInstallCheck = false`) since
most packages don't define one.

```nix
mkGoPackage {
  # ...
  doInstallCheck = true;
  installCheckScript = ''
    $out/bin/butane --version | grep "${version}"
  '';
}
```

### Reproducibility

All build environments set `SOURCE_DATE_EPOCH` to the modification time of
the most recent source file. This timestamp replaces non-deterministic
values (current time) in archives, documentation generators, and other
tools that embed dates, improving build reproducibility.

---

## Layer 1: Dependency Fetchers

### `fetchCargoDeps`

Fixed-output derivation that runs `cargo vendor` and returns a directory of
vendored crates. Network access is allowed (FOD) but the output is
hash-verified.

```nix
# lib/derivations.nix
fetchCargoDeps = {
  src,                    # source containing Cargo.lock
  hash,                   # sri hash of vendored output
  sourceRoot ? null,      # subdirectory containing Cargo.toml (optional)
  cargoLock ? null,       # explicit Cargo.lock file (overrides src's)
  cargoPatches ? [],      # patches to apply to Cargo.lock before vendoring
}:
```

**Implementation:**

```nix
builtins.derivation {
  name = "cargo-deps";
  system = defaultSystem;
  builder = "/bin/sh";
  args = [ "-c" ''
    set -euo pipefail
    export PATH="${cargo}/bin:${bootstrapTools}/bin"
    export CARGO_HOME="$TMPDIR/cargo-home"
    mkdir -p "$CARGO_HOME"

    # Extract source to get Cargo.lock
    tar xf "$src" || cp -r "$src" source
    cd ${if sourceRoot != null then sourceRoot else "$(ls -d */)"}

    # Apply cargo patches if any
    ${builtins.concatStringsSep "\n" (builtins.map (p: "patch -p1 < ${p}") cargoPatches)}

    # Vendor all dependencies
    cargo vendor --locked "$out"
  '' ];

  inherit src;
  outputHash = hash;
  outputHashMode = "recursive";
  outputHashAlgo = "sha256";
}
```

**Usage:**

```nix
cargoDeps = fetchCargoDeps {
  inherit src;
  hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
};
```

**Hash discovery workflow:**

```sh
# First time — use a fake hash, read the error for the real one:
aos prefetch --cargo-deps ./path/to/source
# Or: set hash = lib.fakeHash and read the build failure message
```

### `fetchGoModules`

Fixed-output derivation that runs `go mod download` and returns the module
cache directory. Similar pattern.

```nix
fetchGoModules = {
  src,                    # source containing go.sum
  hash,                   # sri hash of module cache output
  sourceRoot ? null,      # subdirectory containing go.mod
}:
```

**Implementation:**

```nix
builtins.derivation {
  name = "go-modules";
  system = defaultSystem;
  builder = "/bin/sh";
  args = [ "-c" ''
    set -euo pipefail
    export PATH="${go}/bin:${bootstrapTools}/bin"
    export GOPATH="$out"
    export GOCACHE="$TMPDIR/go-cache"
    export GOFLAGS="-mod=mod"

    tar xf "$src" || cp -r "$src" source
    cd ${if sourceRoot != null then sourceRoot else "$(ls -d */)"}

    go mod download -x
  '' ];

  inherit src;
  outputHash = hash;
  outputHashMode = "recursive";
  outputHashAlgo = "sha256";
}
```

### `fetchPypiDeps`

For completeness, Python packages can use a similar pattern. Deferred until
an AOS package actually needs it.

---

## Layer 2: Phase Generators

Phase generators are **functions** that accept configuration (like the vendored
deps directory) and return a phase list compatible with `mkDerivation.phases`.

These replace the static phase lists in `stdenv/phases.nix` with parameterized
versions. Every phase generator produces the full canonical phase sequence
(unpack through fixup), with language-specific configure/build/check/install
in the middle.

### `cargoPhases`

```nix
# stdenv/phases.nix
cargoPhases = {
  cargoDeps,                     # output of fetchCargoDeps
  cargoFlags ? "",               # extra flags for cargo build
  buildType ? "release",         # "release" or "debug"
  checkType ? buildType,         # build type for tests (can differ)
  cargoTestFlags ? "",           # extra flags for cargo test
  buildFeatures ? [],            # cargo features to enable
  buildNoDefaultFeatures ? false,
  installBins ? true,            # install binaries from target/<type>/
  installLibs ? false,           # install .so/.a from target/<type>/
  doCheck ? true,
  doParallelCheck ? true,
}:
[
  unpackPhase
  {
    name = "configure";
    script = ''
      export CARGO_HOME="$TMPDIR/cargo"
      mkdir -p "$CARGO_HOME"

      # Point cargo at vendored deps
      mkdir -p .cargo
      cat > .cargo/config.toml << 'EOF'
      [source.crates-io]
      replace-with = "vendored-sources"

      [source.vendored-sources]
      directory = "${cargoDeps}"
      EOF
    '';
  }
  {
    name = "build";
    script = ''
      cargo build \
        --${buildType} \
        --frozen \
        --offline \
        ${if buildNoDefaultFeatures then "--no-default-features" else ""} \
        ${if buildFeatures != [] then "--features ${builtins.concatStringsSep "," buildFeatures}" else ""} \
        -j$NIX_BUILD_CORES \
        ${cargoFlags}
    '';
  }
  {
    name = "check";
    script = if doCheck then ''
      cargo test \
        --${checkType} \
        --frozen \
        --offline \
        ${if !doParallelCheck then "-- --test-threads=1" else ""} \
        ${cargoTestFlags}
    '' else ''
      echo ">>> check phase disabled (doCheck = false)"
    '';
  }
  {
    name = "install";
    script = ''
      ${if installBins then ''
        mkdir -p "$out/bin"
        find target/${buildType} -maxdepth 1 -type f -executable \
          ! -name '*.d' -exec install -m 755 {} "$out/bin/" \;
      '' else ""}
      ${if installLibs then ''
        mkdir -p "$out/lib"
        find target/${buildType} -maxdepth 1 \
          \( -name '*.so' -o -name '*.a' -o -name '*.dylib' \) \
          -exec install -m 644 {} "$out/lib/" \;
      '' else ""}
    '';
  }
  fixupPhase
];
```

### `goPhases`

```nix
goPhases = {
  goModules ? null,              # output of fetchGoModules (null = vendored in source)
  goPackage ? ".",               # Go package path to build
  goOutput ? null,               # output binary name (default: pname)
  cgoEnabled ? false,            # enable CGO
  ldflags ? "-s -w",            # Go linker flags
  tags ? [],                     # Go build tags
  doCheck ? true,
  goTestFlags ? "./...",         # packages to test
  doParallelCheck ? true,
}:
[
  unpackPhase
  {
    name = "configure";
    script = ''
      export GOPATH="$TMPDIR/go"
      export GOCACHE="$TMPDIR/go-cache"
      export GOFLAGS="-trimpath"
      export CGO_ENABLED=${if cgoEnabled then "1" else "0"}
      mkdir -p "$GOPATH" "$GOCACHE"

      ${if goModules != null then ''
        # Use pre-fetched modules
        export GOPATH="${goModules}"
        export GOFLAGS="$GOFLAGS -mod=vendor"
      '' else ''
        # Source includes vendored deps (vendor/)
        if [ -d vendor ]; then
          export GOFLAGS="$GOFLAGS -mod=vendor"
        fi
      ''}
    '';
  }
  {
    name = "build";
    script = ''
      go build \
        -ldflags "${ldflags}" \
        ${if tags != [] then "-tags ${builtins.concatStringsSep "," tags}" else ""} \
        -o "''${goOutput:-$pname}" \
        ${goPackage}
    '';
  }
  {
    name = "check";
    script = if doCheck then ''
      go test \
        -v \
        ${if !doParallelCheck then "-p 1" else ""} \
        ${if tags != [] then "-tags ${builtins.concatStringsSep "," tags}" else ""} \
        ${goTestFlags}
      go vet ${goTestFlags}
    '' else ''
      echo ">>> check phase disabled (doCheck = false)"
    '';
  }
  {
    name = "install";
    script = ''
      mkdir -p "$out/bin"
      install -m 755 "''${goOutput:-$pname}" "$out/bin/"
    '';
  }
  fixupPhase
];
```

### C/C++ Phase Generators

The existing `autoconfPhases`, `cmakePhases`, and `mesonPhases` are updated
to include a check phase:

```nix
autoconfPhases = {
  doCheck ? true,
  checkTarget ? "check",
  ...
}:
[
  unpackPhase
  configurePhase  # ./configure --prefix=$out
  buildPhase      # make -j$NIX_BUILD_CORES
  {
    name = "check";
    script = if doCheck then ''
      make ${checkTarget} -j$NIX_BUILD_CORES
    '' else ''
      echo ">>> check phase disabled"
    '';
  }
  installPhase    # make install
  fixupPhase
];

cmakePhases = {
  doCheck ? true,
  ...
}:
[
  unpackPhase
  configurePhase  # cmake -B build
  buildPhase      # cmake --build build
  {
    name = "check";
    script = if doCheck then ''
      cd build && ctest --output-on-failure -j$NIX_BUILD_CORES
    '' else ''
      echo ">>> check phase disabled"
    '';
  }
  installPhase    # cmake --install build
  fixupPhase
];
```

---

## Layer 3: Build Environment Functions

Convenience wrappers that compose fetchers + phases + implicit deps into a
single mkDerivation call. These are the primary interface for most packages.

### `mkCargoPackage`

```nix
mkCargoPackage = args@{
  pname,
  version,
  src,
  cargoDeps,                        # from fetchCargoDeps
  cargoFlags ? "",
  buildType ? "release",
  checkType ? buildType,
  cargoTestFlags ? "",
  buildFeatures ? [],
  buildNoDefaultFeatures ? false,
  installBins ? true,
  installLibs ? false,
  doCheck ? true,
  doParallelCheck ? true,
  doInstallCheck ? false,
  installCheckScript ? "",
  dontStrip ? false,
  separateDebugInfo ? false,
  dontPatchELF ? false,
  dontValidateRunpath ? false,
  buildDeps ? [],
  runtimeDeps ? [],
  ...
}:
mkDerivation (removeCargoAttrs args // {
  # Rust toolchain is an implicit build dep
  buildDeps = [ rust ] ++ buildDeps;

  # Standard cargo phases with vendored deps, check, and fixup
  phases = cargoPhases {
    inherit cargoDeps cargoFlags buildType checkType cargoTestFlags
            buildFeatures buildNoDefaultFeatures
            installBins installLibs doCheck doParallelCheck;
  };

  # Fixup controls passed through to the fixup phase
  inherit dontStrip separateDebugInfo dontPatchELF dontValidateRunpath;

  # Install check (runs after fixup against $out)
  inherit doInstallCheck installCheckScript;
});
```

**Usage (nginx-acme rewritten):**

```nix
# pkgs/web/nginx-acme.nix
{ mkCargoPackage, fetchurl, fetchCargoDeps, pkg-config, llvm, nginx, openssl }:

let version = "0.3.1"; in
let
  src = fetchurl {
    urls = [ "https://github.com/nginx/nginx-acme/archive/refs/tags/v${version}.tar.gz" ];
    hash = "sha256-vj09EPBCkwo780hzFpjq23AD0iSoY8U7cZzNKHIVcsM=";
  };
in
mkCargoPackage {
  pname = "nginx-acme";
  inherit version src;

  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  cargoFlags = "--lib";
  installBins = false;
  installLibs = true;
  doCheck = false;  # tests require nginx runtime

  buildDeps = [ pkg-config llvm ];
  runtimeDeps = [ nginx openssl ];

  LIBCLANG_PATH = "${llvm}/lib";
  NGINX_BUILD_DIR = "${nginx}";

  postInstall = ''
    mkdir -p $out/lib/nginx/modules
    mv $out/lib/libngx_http_acme_module.so \
       $out/lib/nginx/modules/ngx_http_acme_module.so
  '';
}
```

### `mkGoPackage`

```nix
mkGoPackage = args@{
  pname,
  version,
  src,
  goModules ? null,                 # from fetchGoModules (null = vendored in source)
  goPackage ? ".",
  goOutput ? null,
  cgoEnabled ? false,
  ldflags ? "-s -w",
  tags ? [],
  doCheck ? true,
  goTestFlags ? "./...",
  doParallelCheck ? true,
  doInstallCheck ? false,
  installCheckScript ? "",
  dontStrip ? false,
  buildDeps ? [],
  runtimeDeps ? [],
  ...
}:
mkDerivation (removeGoAttrs args // {
  # Go toolchain is an implicit build dep
  buildDeps = [ go ] ++ buildDeps;

  # Standard go phases with check and fixup
  phases = goPhases {
    inherit goModules goPackage goOutput cgoEnabled ldflags tags
            doCheck goTestFlags doParallelCheck;
  };

  inherit dontStrip doInstallCheck installCheckScript;
});
```

**Usage (butane rewritten):**

```nix
# pkgs/boot/butane.nix — before
{ mkDerivation, fetchurl, make }:
...
mkDerivation {
  pname = "butane";
  buildDeps = [ make ];
  phases = [
    { name = "unpack"; script = ''tar xf $src; cd butane-${version}''; }
    { name = "build"; script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o butane -ldflags "-s -w ..." ./internal
      ''; }
    { name = "install"; script = ''mkdir -p $out/bin; install -m 755 butane $out/bin/''; }
  ];
}

# pkgs/boot/butane.nix — after
{ mkGoPackage, fetchurl }:
...
mkGoPackage {
  pname = "butane";
  inherit version src;
  goPackage = "./internal";
  goOutput = "butane";
  ldflags = "-s -w -X github.com/coreos/butane/internal/version.Raw=v${version}";
}
```

---

## Fixup Phase Implementation

The shared fixup phase is defined once and used by all build environments.
It replaces the current minimal `fixupPhase` in `stdenv/phases.nix`:

```nix
fixupPhase = {
  name = "fixup";
  script = ''
    # --- Strip debug symbols ---
    if [ -z "''${dontStrip:-}" ]; then
      echo "stripping debug symbols..."
      find "$out" -type f -name '*.so*' -exec strip -S {} \; 2>/dev/null || true
      find "$out" -type f -name '*.a' -exec strip -S {} \; 2>/dev/null || true
      find "$out/bin" -type f -exec strip -s {} \; 2>/dev/null || true
    fi

    # --- Patch shebangs ---
    if [ -z "''${dontPatchShebangs:-}" ]; then
      echo "patching shebangs..."
      for f in $(find "$out" -type f -executable); do
        head -c 2 "$f" | grep -q '#!' || continue
        # Read the shebang line
        interp=$(head -1 "$f" | sed 's/^#!//' | sed 's/ .*//')
        case "$interp" in
          /usr/bin/env)
            # Replace /usr/bin/env <prog> with absolute path from PATH
            prog=$(head -1 "$f" | sed 's|^#!/usr/bin/env  *||' | sed 's/ .*//')
            abs=$(command -v "$prog" 2>/dev/null || true)
            if [ -n "$abs" ]; then
              sed -i "1s|.*|#!$abs|" "$f"
            fi
            ;;
          /usr/bin/*|/bin/*|/usr/local/bin/*)
            prog=$(basename "$interp")
            abs=$(command -v "$prog" 2>/dev/null || true)
            if [ -n "$abs" ]; then
              sed -i "1s|.*|#!$abs|" "$f"
            fi
            ;;
        esac
      done
    fi

    # --- Patch ELF RPATH ---
    if [ -z "''${dontPatchELF:-}" ] && command -v patchelf >/dev/null; then
      echo "shrinking ELF RPATHs..."
      for f in $(find "$out" -type f \( -name '*.so*' -o -executable \)); do
        patchelf --shrink-rpath "$f" 2>/dev/null || true
      done
    fi

    # --- Validate runpath ---
    if [ -z "''${dontValidateRunpath:-}" ]; then
      echo "validating ELF runpaths..."
      _validateRunpath() {
        for f in $(find "$out" -type f -executable); do
          file "$f" | grep -q ELF || continue
          needed=$(patchelf --print-needed "$f" 2>/dev/null) || continue
          rpath=$(patchelf --print-rpath "$f" 2>/dev/null) || continue
          for lib in $needed; do
            found=0
            IFS=':' read -ra dirs <<< "$rpath"
            for dir in "''${dirs[@]}"; do
              if [ -f "$dir/$lib" ]; then
                found=1
                break
              fi
            done
            # Also check standard locations
            if [ "$found" = 0 ] && [ -f "$out/lib/$lib" ]; then
              found=1
            fi
            if [ "$found" = 0 ]; then
              echo "WARNING: $f needs $lib but it's not in RPATH"
            fi
          done
        done
      }
      _validateRunpath
    fi

    # --- Move docs ---
    if [ -z "''${dontMoveDocs:-}" ]; then
      for d in man doc info; do
        if [ -d "$out/$d" ]; then
          mkdir -p "$out/share"
          mv "$out/$d" "$out/share/"
        fi
      done
    fi
  '';
};
```

---

## Cargo Workspace Support

Many Rust projects use Cargo workspaces (multiple crates in one repo).
`mkCargoPackage` supports this via:

```nix
mkCargoPackage {
  pname = "my-tool";
  inherit version src;

  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-...";
  };

  # Build only specific crates from the workspace
  cargoFlags = "--package my-tool-cli --package my-tool-lib";

  # Test the whole workspace
  cargoTestFlags = "--workspace";
}
```

### Cargo Feature Selection

```nix
mkCargoPackage {
  # ...
  buildNoDefaultFeatures = true;
  buildFeatures = [ "ssl" "compression" ];
}
```

---

## `passthru` Conventions

Build environment functions set standard `passthru` attributes for
downstream tooling and CI:

```nix
result.passthru = {
  # The phase list, for inspection and manipulation
  phases = ...;

  # External test derivations (for CI, not run during package build)
  tests = {
    integration = mkDerivation { ... };  # optional
  };

  # The unwrapped package (before wrapProgram, if applicable)
  unwrapped = ...;  # optional

  # Update metadata for automated version bumping
  updateScript = ...;  # optional, future
};
```

`passthru.tests` is particularly useful — it allows expensive integration
tests to run in CI without blocking every package build. The `check` phase
handles fast unit tests; `passthru.tests` handles slow integration tests:

```nix
mkGoPackage {
  pname = "butane";
  # ... fast unit tests run in check phase ...

  passthru.tests.integration = mkDerivation {
    name = "butane-integration-test";
    buildDeps = [ self.butane self.ignition ];
    phases = [{ name = "test"; script = ''
      butane < test-config.bu | ignition --validate
      touch $out
    ''; }];
  };
};
```

---

## Binary Wrapping

Some packages need environment variables set at runtime (e.g., `PYTHONPATH`
for Python tools, `GI_TYPELIB_PATH` for GObject introspection). A
`wrapProgram` utility handles this:

```nix
# In postInstall or a custom phase:
postInstall = ''
  wrapProgram $out/bin/my-tool \
    --prefix PATH : ${lib.makeBinPath [ coreutils ]} \
    --set MY_CONFIG_DIR /etc/my-tool
'';
```

`wrapProgram` creates a shell wrapper that sets/prepends/appends environment
variables before exec'ing the real binary. The real binary is moved to
`$out/bin/.my-tool-wrapped`.

### Wrapping Operations

| Flag | Effect |
|------|--------|
| `--prefix VAR : value` | Prepend to `$VAR` |
| `--suffix VAR : value` | Append to `$VAR` |
| `--set VAR value` | Set `$VAR` unconditionally |
| `--set-default VAR value` | Set `$VAR` only if unset |
| `--unset VAR` | Unset `$VAR` |
| `--run COMMAND` | Run command before exec |

---

## `remove-references-to`

Sometimes a built package accidentally retains a reference to a build-only
dependency (e.g., cmake, python, or a test framework). This bloats the
runtime closure. `remove-references-to` patches the binary to eliminate
the reference:

```nix
postInstall = ''
  remove-references-to -t ${cmake} $out/bin/my-tool
  remove-references-to -t ${python3} $out/lib/libfoo.so
'';
```

This replaces the store hash with a dummy value, breaking the reference
without changing the file size. The fixup phase's `validate-runpath` will
warn if removing a reference breaks a library lookup.

---

## Wiring into pkgs/default.nix

Build environment functions need access to the toolchain packages (rust, go)
from the package set. They're defined in `pkgs/default.nix` after the
toolchain packages are available:

```nix
# pkgs/default.nix (additions)
let
  # ... existing code ...

  # Import phase generators
  phases = import ../stdenv/phases.nix;

  # Build environment helpers
  fetchCargoDeps = args: lib.fetchCargoDeps (args // {
    cargo = self.rust;               # AOS-built Rust/Cargo
    inherit bootstrapTools;
  });

  fetchGoModules = args: lib.fetchGoModules (args // {
    go = self.go;                    # AOS-built Go
    inherit bootstrapTools;
  });

  mkCargoPackage = args:
    let
      cargoArgs = extractCargoArgs args;
      restArgs = removeCargoArgs args;
    in
    mkDerivation (restArgs // {
      buildDeps = [ self.rust ] ++ (args.buildDeps or []);
      phases = phases.cargoPhases cargoArgs;
    });

  mkGoPackage = args:
    let
      goArgs = extractGoArgs args;
      restArgs = removeGoArgs args;
    in
    mkDerivation (restArgs // {
      buildDeps = [ self.go ] ++ (args.buildDeps or []);
      phases = phases.goPhases goArgs;
    });

  self = {
    inherit mkDerivation fetchurl lib;
    inherit mkCargoPackage mkGoPackage;
    inherit fetchCargoDeps fetchGoModules;
  }
  // discoverPackages ./.
  // { ... };
in
self
```

Packages request these via callPackage's auto-fill:

```nix
# Any package can ask for mkCargoPackage, fetchCargoDeps, etc.
{ mkCargoPackage, fetchurl, fetchCargoDeps, openssl }:
...
```

---

## File Layout

```
lib/
  derivations.nix          # fetchCargoDeps, fetchGoModules added here
stdenv/
  phases.nix               # cargoPhases, goPhases become parameterized functions
                           # fixupPhase expanded with strip/patch/validate
pkgs/
  default.nix              # mkCargoPackage, mkGoPackage wired with toolchain
```

No new files needed. The fetchers go in `lib/derivations.nix` alongside
`fetchurl` and `fetchgit`. The phase generators stay in `stdenv/phases.nix`.
The build env functions are defined in `pkgs/default.nix` where they have
access to the package set.

---

## Hash Discovery Workflow

Both `fetchCargoDeps` and `fetchGoModules` require a content hash. To discover
the hash for a new package:

1. Set `hash = lib.fakeHash` (or `hash = ""`)
2. Run `aos build pkgs.<name>`
3. The build fails with "hash mismatch" and prints the actual hash
4. Copy the hash into the package definition

The `aos prefetch` command can be extended to support this:

```sh
# Prefetch cargo deps for a source tarball
aos prefetch --cargo-deps https://github.com/.../v0.3.1.tar.gz

# Prefetch go modules for a source tarball
aos prefetch --go-modules https://github.com/.../v1.7.24.tar.gz
```

---

## Migration Path

Existing packages continue to work as-is. The new build environment functions
are opt-in. Migration happens incrementally:

1. **Phase 1**: Implement fixup phase (strip, patchShebangs, patchELF,
   validate-runpath) in `stdenv/phases.nix`. All existing phase templates
   gain the fixup phase. Implement `fetchCargoDeps` and `fetchGoModules`
   in `lib/derivations.nix`.

2. **Phase 2**: Upgrade phase templates to parameterized functions with
   check phases. Define `mkCargoPackage` and `mkGoPackage` in
   `pkgs/default.nix`. Fix nginx-acme as the first Rust package.

3. **Phase 3**: Migrate existing Go packages to `mkGoPackage` one at a time.
   Add `doCheck = true` as packages are verified to have passing tests.
   No rush — the old manual-phase style continues to work.

4. **Phase 4**: Add `wrapProgram`, `remove-references-to` utilities.
   Extend `aos prefetch` for `--cargo-deps` and `--go-modules`.

---

## Comparison with Guix and nixpkgs

| Aspect | Guix | nixpkgs | AOS |
|--------|------|---------|-----|
| Build system type | First-class `<build-system>` object | Per-language `buildXxxPackage` functions | Per-language `mkXxxPackage` functions |
| Intermediate repr | `bag` → derivation | Direct derivation | Direct mkDerivation call |
| Phase customization | `modify-phases` macro | `override{Attrs,Phase}` | `replacePhase`, `addPhaseAfter`, etc. |
| Standard phases | unpack → patch → configure → build → check → install → fixup → strip → validate | unpack → patch → configure → build → check → install → fixup → installCheck → dist | unpack → patch → configure → build → check → install → fixup → installCheck |
| Check phase | On by default, `#:tests?` to disable | Off by default (`doCheck`), on for some builders | On by default, `doCheck` to disable |
| Fixup | strip + patchShebangs + patchELF + validate-runpath + moveDocs | strip + patchShebangs + patchELF + moveLib + moveDocs + wrapQtApps | strip + patchShebangs + patchELF + validate-runpath + moveDocs |
| Dep fetching | `#:cargo-inputs` as Guix packages | FOD fetchers (`fetchCargoTarball`) | FOD fetchers (`fetchCargoDeps`, `fetchGoModules`) |
| Binary wrapping | Per-build-system wrap phases | `wrapProgram` / `makeWrapper` | `wrapProgram` utility |
| Debug info | Not separated by default | `separateDebugInfo` → `$debug` output | `separateDebugInfo` → `$debug` output |
| Composition | Build systems inherit from gnu-build-system | Builders are independent | Build env functions call mkDerivation directly |
| Implicit deps | Per-build-system (gcc, rust, go, etc.) | Per-builder (gcc always, rust/go per builder) | Per-build-env function (only what's needed) |

AOS takes inspiration from both systems:

- From **Guix**: check-by-default, comprehensive fixup phases, the principle
  that build systems should handle the full lifecycle (not just build+install)
- From **nixpkgs**: FOD-based dependency fetching, `separateDebugInfo`,
  `wrapProgram`, `remove-references-to`, `passthru.tests`
- From **[build-modules](https://github.com/DavHau/build-modules)**: the
  insight that stdenv's C-centric defaults are a poor fit for non-C languages,
  and that build environments should be language-native from the start

AOS avoids Guix's `<build-system>` type indirection and nixpkgs' 30 years
of accumulated complexity. Build environment functions are just functions —
no special types, no bag intermediate representation, no implicit hook
infrastructure.

---

## Non-Goals

- **Cross-compilation**: not needed now. Build envs target x86_64-linux only.
- **Python build env**: deferred until an AOS package needs Python deps from
  PyPI. Currently all Python packages are build-from-source.
- **Dynamic module loading**: no plugin architecture. Build envs are
  statically defined functions.
- **Automatic hash updates**: `aos prefetch` integration is a follow-up.
- **Multi-output splitting**: (lib, dev, doc as separate outputs) — deferred.
  Would require changes to `mkDerivation`'s output handling.
- **dist phase**: (producing source tarballs) — not relevant for AOS.
