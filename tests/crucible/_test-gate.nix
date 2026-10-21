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
##! family                       selections                       consumers
##! apacheTests (debug)          per-package test and dev builds  most gates
##! gplTests (debug)             qemu plugin, debug gateway       plugin gates
##! apacheRelease                release examples and harnesses   VM flights
##! apacheReleaseTestSupport     release examples, test-support   ack-poll flights
##! ```
##!
##! Each family depends on RFC-0015 dependency artifacts built from a
##! manifest-only dummy workspace, compiles first-party code once for every
##! selection, and publishes the executables with a manifest. Development
##! builds use aos-dev's persistent incremental target directory instead of
##! the artifact seed. A gate depends on the family outputs and runs tests
##! through `crucible-cargo`, which accepts the gate's original `cargo test`,
##! `cargo run`, or `cargo build` command line and never compiles.
##!
##! A selection is one Cargo feature resolution: package set, features, and
##! profile (`_workspace-test-selections.nix`). Keeping selections separate
##! preserves exactly what each former Cargo invocation compiled, including
##! cfg(feature) differences between `-p crucible` and `-p crucible
##! --features test-double`.
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
##!         crucible-cargo test -p crucible --lib -- --test-threads=1
##!       '';
##!     }
##!   ];
##! }
##! ```
##!
##! `builds` selects families; the default is both debug test families.
##! `mkCrucibleBinaries` copies named executables into a small output for VM
##! root filesystems, so a flight closure never retains a whole family.
{
  pkgs,
  lib,
}: let
  workspaceTests = pkgs.crucible-controller.passthru.workspaceTests;
  inherit (workspaceTests) runner;
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
        buildDeps = [runner pkgs.coreutils] ++ builds ++ buildDeps;
        CRUCIBLE_CARGO_BUILDS = buildsPath builds;
        phases = [unpackPhase configurePhase] ++ phases;
      }
    );

  # Copies the named selections of each family into a small output with the
  # same layout, for VM root filesystems that must not retain whole
  # families. `selections` uses crucible-cargo identities, such as
  # "crucible-qemu" or "build:crucible-shmem". `targets`, when given, keeps
  # only those `kind:name` rows (for example "lib:crucible_qemu"), so a gate
  # that runs `--lib` does not carry every integration-test executable.
  mkCrucibleTestSubset = {
    pname,
    builds ? debugBuilds,
    selections,
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
      SELECTIONS = lib.concatStringsSep "\n" selections;
      TARGETS = lib.concatStringsSep "\n" targets;
      phases = [
        {
          name = "install";
          script = ''
            set -eu
            printf '%s\n' "$SELECTIONS" > "$TMPDIR/selections"
            printf '%s' "$TARGETS" > "$TMPDIR/targets"
            index=0
            for build in ${lib.concatMapStringsSep " " toString builds}; do
              index=$((index + 1))
              target="$out/$index"
              mkdir -p "$target/libexec" "$target/doctests"
              cp "$build/build-info" "$target/build-info"
              cp -R "$build/packages" "$target/packages"
              awk -F '\t' '
                FILENAME == ARGV[1] { wanted[$0] = 1; next }
                FILENAME == ARGV[2] { targets[$0] = 1; filtered = 1; next }
                wanted[$1] && (!filtered || targets[$3 ":" $4])
              ' "$TMPDIR/selections" "$TMPDIR/targets" "$build/manifest.tsv" \
                > "$target/manifest.tsv"
              cut -f 6 "$target/manifest.tsv" | sort -u | while read -r stored; do
                cp "$build/$stored" "$target/$stored"
              done
              while read -r selection; do
                if [ -e "$build/doctests/$selection.status" ]; then
                  cp "$build/doctests/$selection".* "$target/doctests/"
                fi
              done < "$TMPDIR/selections"
            done
            # Every requested selection must exist in some family.
            while read -r selection; do
              cat "$out"/*/manifest.tsv | cut -f 1 | grep -Fxq "$selection" || {
                echo "selection '$selection' is not built by the requested families" >&2
                exit 1
              }
            done < "$TMPDIR/selections"
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
  #   executables = { flight = "build --release -p crucible-qemu --example x"; };
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
