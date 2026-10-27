##! Shared builders for Crucible gates that run Rust tests.
##!
##! Design
##! ------
##! Crucible gates once compiled the workspace themselves: each copied the
##! repository, wrote a vendored Cargo configuration, and ran `cargo test`
##! into a private target directory. About 330 gate files repeated that
##! compile, so a source edit recompiled the full dependency graph once per
##! gate, and the serial green-before-advance chain repeated it again.
##!
##! Rust now compiles in a small set of first-class derivations owned by the
##! Crucible package (`pkgs/tools/crucible/_workspace-tests.nix`):
##!
##! ```text
##! family              selections                          consumers
##! apacheTests         unified debug tests, plus CLI       most gates
##!                     test-double, recovery faults, and
##!                     production qemu examples
##! gplTests            plugin and debug-gateway tests,     plugin gates
##!                     production plugin cdylib
##! apacheRelease       unified release harnesses, shipped  VM flights
##!                     CLI, production examples
##! gplRelease          plugin release harness              campaign-mode guests
##! ```
##!
##! Each family depends on RFC-0015 dependency artifacts built from a
##! manifest-only dummy workspace and compiles first-party code in one
##! derivation. Development builds use aos-dev's persistent incremental
##! target directory instead of the artifact seed. A gate depends on the
##! family outputs and runs tests through `crucible-cargo`, which accepts the
##! gate's original `cargo test`, `cargo run`, or `cargo build` command line
##! and never compiles.
##!
##! A selection is one Cargo feature resolution: package set, features, and
##! profile (`_workspace-test-selections.nix`). Cargo recompiles every crate
##! whose features differ between resolutions, so each family unifies the
##! features its gates request into one selection per profile. Only
##! requests whose features change what a test observes, such as the CLI's
##! test-double surface or the fault-injection builds, get their own
##! selection; each says why. The runner maps every gate request to its
##! selection and skips targets whose required-features the request would
##! not have enabled, so a gate runs the targets its former Cargo command
##! ran.
##!
##! A gate keeps its own Cargo invocation only for a genuinely different
##! build configuration, such as compile-time environment variables or a
##! reconstructed external workspace; each exception says so at the call.
##!
##! API
##! ---
##! `mkCrucibleTestGate` wraps `pkgs.mkDerivation`. It unpacks the gate's
##! run-time source at `/build/source`, where the executables were compiled,
##! writes the vendored Cargo configuration that run-time `cargo metadata`
##! calls need, and puts `crucible-cargo` on PATH. The gate supplies its
##! own phases, environment, assertions, and result lines unchanged:
##!
##! ```nix
##! mkCrucibleTestGate {
##!   pname = "crucible-phase1-example";
##!   ATTR_PATH = attrPath;
##!   phases = [
##!     {
##!       name = "run-example";
##!       script = ''
##!         crucible-cargo test -p crucible-engine --lib -- --test-threads=1
##!       '';
##!     }
##!   ];
##! }
##! ```
##!
##! Gates that require individually named tests call `crucible-exact-tests`
##! (`pkgs/tools/crucible/crucible-exact-tests.sh`), which checks that each
##! name is listed once and runs them all with `--exact` in one process per
##! executable, instead of one listing and one test process per name.
##!
##! `builds` selects families; the default is both debug test families.
##! `mkCrucibleBinaries` copies named executables into a small output for VM
##! root filesystems, so a flight closure never retains a whole family.
{
  pkgs,
  lib,
}: let
  workspaceTests = pkgs.crucible-controller.passthru.workspaceTests;
  inherit (workspaceTests) runner exactTests;
  cargoDeps = pkgs.crucible-controller.passthru.cargoDeps;
  defaultSource = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};

  # The executables embed `/build/source` paths, so the run-time source must
  # unpack there. Gates that read files at run time get them from `src`.
  unpackPhase = {
    name = "unpack";
    script = ''
      cp -R "$src" source
      chmod -R u+w source
      cd source
    '';
  };

  # Tests that inspect the workspace call `cargo metadata` offline.
  configurePhase = {
    name = "configure";
    script = ''
      export CARGO_HOME="$TMPDIR/cargo"
      mkdir -p "$CARGO_HOME" .cargo
      sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
        > .cargo/config.toml
    '';
  };

  buildsPath = builds: lib.concatStringsSep ":" (map toString builds);

  # Debug test families every gate can run without naming them.
  debugBuilds = [workspaceTests.apacheTests workspaceTests.gplTests];
  # Gates that also run `cargo test --release` selections.
  releaseBuilds = debugBuilds ++ [workspaceTests.apacheRelease];
in {
  inherit workspaceTests runner debugBuilds releaseBuilds;

  mkCrucibleTestGate = {
    src ? defaultSource,
    builds ? debugBuilds,
    buildDeps ? [],
    phases,
    ...
  } @ args:
    pkgs.mkDerivation (
      (removeAttrs args ["builds"])
      // {
        inherit src;
        version = args.version or "0";
        buildDeps = [runner exactTests pkgs.coreutils] ++ builds ++ buildDeps;
        CRUCIBLE_CARGO_BUILDS = buildsPath builds;
        phases = [unpackPhase configurePhase] ++ phases;
      }
    );

  # Copies the executables that serve the named test requests into a small
  # output with the family layout, for VM root filesystems that must not
  # retain whole families. `requests` uses crucible-cargo identities, such
  # as "crucible-qemu" or "crucible[test-double]". `targets`, when given,
  # keeps only those `kind:name` rows (for example "lib:crucible_qemu"), so
  # a gate that runs `--lib` does not carry every integration-test
  # executable.
  mkCrucibleTestSubset = {
    pname,
    builds ? debugBuilds,
    requests,
    targets ? [],
  }:
    pkgs.mkDerivation {
      inherit pname;
      version = "0";
      src = null;
      buildDeps = [pkgs.coreutils pkgs.gawk] ++ builds;
      runtimeDeps = lib.unique (lib.concatMap (build: build.passthru.nativeRuntimeDeps) builds);
      # The families already removed build-only references; the generic
      # scrub would also rewrite the store-path fixtures tests compare.
      dontNukeRefs = true;
      dontStrip = true;
      dontPatchELF = true;
      REQUESTS = lib.concatStringsSep "\n" requests;
      TARGETS = lib.concatStringsSep "\n" targets;
      phases = [
        {
          name = "install";
          script = ''
            set -eu
            printf '%s\n' "$REQUESTS" > "$TMPDIR/requests"
            printf '%s' "$TARGETS" > "$TMPDIR/targets"
            index=0
            for build in ${lib.concatMapStringsSep " " toString builds}; do
              index=$((index + 1))
              target="$out/$index"
              mkdir -p "$target/libexec" "$target/doctests" "$target/nix-support"
              cp "$build/build-info" "$target/build-info"
              cp -R "$build/packages" "$target/packages"
              # The executables are compressed, so their run-time libraries
              # stay in the closure only through the family's list.
              cp "$build/nix-support/executable-references" "$target/nix-support/"

              # The aliases of the requested tests, and the rows they serve:
              # harnesses of the requested packages and kinds, plus the
              # binaries those harnesses run through CARGO_BIN_EXE_*.
              awk -F '\t' '
                FILENAME == ARGV[1] { wanted[$0] = 1 }
                FILENAME == ARGV[2] && $1 == "test" && wanted[$2]
              ' "$TMPDIR/requests" "$build/aliases.tsv" > "$target/aliases.tsv"
              awk -F '\t' '
                FILENAME == ARGV[1] { targets[$0] = 1; filtered = 1; next }
                FILENAME == ARGV[2] {
                  packages = $2
                  sub(/\[.*/, "", packages)
                  count = split(packages, names, "+")
                  kinds = split($3, served, ",")
                  for (i = 1; i <= count; i++) {
                    for (k = 1; k <= kinds; k++) harness[$4, names[i], served[k]] = 1
                    binaries[$4, names[i]] = 1
                  }
                  next
                }
                ($2 == "harness" && harness[$1, $5, $3]) \
                  || ($2 == "artifact" && $3 == "bin" && binaries[$1, $5]) {
                  if (!filtered || targets[$3 ":" $4]) print
                }
              ' "$TMPDIR/targets" "$target/aliases.tsv" "$build/manifest.tsv" \
                > "$target/manifest.tsv"
              cut -f 6 "$target/manifest.tsv" | sort -u | while read -r stored; do
                cp "$build/$stored" "$target/$stored"
              done
              if [ -d "$build/doctests" ]; then
                cut -f 1 "$target/manifest.tsv" | sort -u | while read -r selection; do
                  [ ! -d "$build/doctests/$selection" ] \
                    || cp -R "$build/doctests/$selection" "$target/doctests/"
                done
              fi
            done

            # Every request must be served by some family.
            while read -r request; do
              cat "$out"/*/aliases.tsv | cut -f 2 | grep -Fxq "$request" || {
                echo "request '$request' is not served by the requested families" >&2
                exit 1
              }
            done < "$TMPDIR/requests"
            ls -d "$out"/* | paste -sd: - > "$TMPDIR/builds"
            mkdir -p "$out/nix-support"
            cp "$TMPDIR/builds" "$out/nix-support/crucible-cargo-builds"
          '';
        }
      ];
    };

  # Shell setup for gates whose runtime script runs inside a VM: the same
  # source location, Cargo configuration, and runner as mkCrucibleTestGate.
  # Add `closures` to the VM's runtime closures.
  mkCrucibleVmRuntime = {
    src ? defaultSource,
    subset,
  }: {
    closures = [src subset runner cargoDeps];
    script = ''
      mkdir -p /build
      rm -rf /build/source
      cp -R ${src} /build/source
      chmod -R u+w /build/source
      cd /build/source
      export CARGO_HOME="$TMPDIR/cargo"
      mkdir -p "$CARGO_HOME" .cargo
      sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
        > .cargo/config.toml
      CRUCIBLE_CARGO_BUILDS=$(cat ${subset}/nix-support/crucible-cargo-builds)
      export CRUCIBLE_CARGO_BUILDS
      export PATH="${runner}/bin:$PATH"
    '';
  };

  # Copies executables resolved from Cargo command lines into $out/bin.
  # `postInstall` runs after the copies; other attributes, such as
  # `dontStrip`, pass through to mkDerivation.
  #
  #   executables = { flight = "build --release -p crucible-qemu-host --example x"; };
  mkCrucibleBinaries = {
    pname,
    builds,
    executables,
    postInstall ? "",
    ...
  } @ args:
    pkgs.mkDerivation ((removeAttrs args ["builds" "executables" "postInstall"])
      // {
        inherit pname;
        version = "0";
        src = null;
        buildDeps = [runner pkgs.coreutils] ++ builds;
        # Executables link the family's native libraries; keep those
        # references through the output scrub.
        runtimeDeps = lib.unique (lib.concatMap (build: build.passthru.nativeRuntimeDeps) builds);
        CRUCIBLE_CARGO_BUILDS = buildsPath builds;
        phases = [
          {
            name = "install";
            script = ''
              mkdir -p "$out/bin"
              ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: command: ''
                  cp "$(crucible-cargo executable ${command})" "$out/bin/${name}"
                  chmod u+w "$out/bin/${name}"
                '')
                executables)}
              ${postInstall}
            '';
          }
        ];
      });
}
