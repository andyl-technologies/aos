##! Crucible workspace test builds: compile once, run from every gate.
##!
##! Crucible gates used to copy the whole repository, write a vendored Cargo
##! configuration, and compile third-party and first-party crates into a
##! private target directory. Every gate repeated nearly the same compile.
##! This file turns that work into a dependency graph:
##!
##! ```text
##! dummy source ─▶ <family>Artifacts   third-party units only (RFC-0015)
##!                        │
##! build source ─▶ <family>             first-party units, every selection
##!                        │             compiled once; executables, manifest,
##!                        │             and recorded doctest results
##!                        ▼
##!                 runner (crucible-cargo) ─▶ gates and VM flights
##! ```
##!
##! A family groups selections that share a license scope and Cargo profile:
##! Apache host tests, GPL-side process tests, Apache release executables,
##! and so on. `_workspace-test-selections.nix` lists the selections. The
##! artifacts derivation replays the same Cargo commands on a manifest-only
##! dummy workspace, so its identity changes only with manifests, the
##! lockfile, the toolchain, and the selection list. Development builds
##! replace that seed with aos-dev's persistent incremental target directory.
##!
##! Each family output contains:
##!
##! ```text
##! build-info            family, profile, and the compile-time source root
##! manifest.tsv          id, role (harness|artifact), kind, name, package, path
##! packages/<name>.env   Cargo's run-time package environment
##! libexec/<sha>-<name>  content-addressed executables (and cdylibs); the
##!                       output scrub removes build-only store paths there
##! doctests/<id>.*       doctest outcomes, replayed with libtest filters
##! ```
##!
##! Doctests are compiled and run once in the family build because rustdoc
##! has no `--no-run` mode; the runner replays the recorded per-test outcome
##! with the gate's own filters.
##!
##! Gates run executables through `crucible-cargo`, which accepts the gates'
##! existing Cargo command lines. Compile-time paths such as
##! `env!("CARGO_MANIFEST_DIR")` name `/build/source`, so a gate unpacks its
##! run-time source at that same sandbox path.
{
  lib,
  mkDerivation,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  version,
  cargoDeps,
  cargoEnv,
  rust,
  buildRustDev,
  buildPkgConfig,
  buildProtobuf,
  openssl,
  sqlite,
  bash,
  coreutils,
  gawk,
  grep,
  sed,
}: let
  selections = import ./_workspace-test-selections.nix;
  buildSource = import ./_cargo-build-source.nix {inherit lib;};
  dummySource = mkCargoDummySource {
    srcRoot = ../../../crates;
    name = "crucible-workspace-tests-dummy-source";
    cargoRoot = "crates";
  };

  nativeBuildDeps = [buildRustDev buildPkgConfig openssl sqlite buildProtobuf];
  nativeRuntimeDeps = [openssl sqlite];

  # Must match crucible-cargo's selection identity.
  selectionId = selection: let
    packages = lib.concatStringsSep "+" (lib.sort (a: b: a < b) selection.packages);
    features = lib.sort (a: b: a < b) (selection.features or []);
  in
    if features == []
    then packages
    else "${packages}[${lib.concatStringsSep "," features}]";

  selectionFlags = profile: selection:
    lib.concatStringsSep " " (
      ["--frozen" "--offline" "-j$NIX_BUILD_CORES"]
      ++ lib.optional (profile == "release") "--release"
      ++ map (package: "-p ${package}") selection.packages
      ++ lib.optional ((selection.features or []) != [])
      "--features ${lib.concatStringsSep "," selection.features}"
      ++ (selection.targets or [])
    );

  # One record per Cargo invocation. `allTargets` adds a second invocation
  # that compiles examples and benches as test harnesses as well.
  testInvocations = profile: selection:
    [
      {
        id = selectionId selection;
        command = "test --no-run ${selectionFlags profile selection}";
      }
    ]
    ++ lib.optional (selection.allTargets or false) {
      id = selectionId selection;
      command = "test --no-run ${selectionFlags profile selection} --all-targets";
    };
  buildInvocations = profile: selection: [
    {
      id = "build:${selectionId selection}";
      command = "build ${selectionFlags profile selection}";
    }
  ];

  shellQuote = value: "'${builtins.replaceStrings ["'"] ["'\"'\"'"] value}'";

  # Re-runs each invocation after the build. Every unit is fresh by then, so
  # Cargo only reports the executables of that exact selection. Cargo also
  # relinks fresh binaries into their uplifted paths, so a binary is copied
  # before the next selection can replace it.
  collectExecutables = invocations: doctestInvocations: ''
    collectRoot="$NIX_BUILD_TOP/crucible-workspace-tests"
    mkdir -p "$collectRoot/libexec" "$collectRoot/packages"
    : > "$collectRoot/manifest.unsorted"

    cargo metadata --format-version 1 --frozen --offline --no-deps \
      > "$collectRoot/metadata.json"

    collect_selection() {
      selection_id=$1
      shift
      cargo "$@" --message-format=json > "$collectRoot/messages.jsonl"
      jq -r --slurpfile metadata "$collectRoot/metadata.json" '
        ($metadata[0].packages
          | map({key: .manifest_path, value: .name}) | from_entries) as $names
        | select(.reason == "compiler-artifact")
        # Only workspace targets; build scripts are compiler executables.
        | select($names[.manifest_path] != null)
        | select(.target.kind | index("custom-build") | not)
        # A cdylib, such as the QEMU plugin, is the artifact gates load.
        | (if .executable != null then .executable
           elif (.target.kind | index("cdylib")) and (.profile.test | not)
           then (.filenames | map(select(endswith(".so"))) | first)
           else null end) as $path
        | select($path != null)
        | [
            (if .profile.test then "harness" else "artifact" end),
            (.target.kind[0]
              | if . == "bin" or . == "test" or . == "bench" or . == "example"
                then . else "lib" end),
            .target.name,
            $names[.manifest_path],
            $path
          ]
        # A non-whitespace separator keeps empty fields from shifting.
        | join("\u001f")
      ' "$collectRoot/messages.jsonl" \
        | while IFS="$(printf '\037')" read -r role kind name package executable; do
            test -n "$package" && test -f "$executable"
            digest=$(sha256sum "$executable" | cut -d ' ' -f 1)
            case $executable in
              *.so) stored="libexec/$digest-''${executable##*/}" ;;
              *) stored="libexec/$digest-$name" ;;
            esac
            if [ ! -e "$collectRoot/$stored" ]; then
              cp "$executable" "$collectRoot/$stored"
              # The workspace test profile asks for no debug info; the DWARF
              # here comes from prebuilt std and is about 95% of each file.
              # Symbols stay, so backtraces still name functions.
              chmod u+w "$collectRoot/$stored"
              strip --strip-debug "$collectRoot/$stored"
            fi
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
              "$selection_id" "$role" "$kind" "$name" "$package" "$stored" \
              >> "$collectRoot/manifest.unsorted"
          done
    }

    ${lib.concatMapStringsSep "\n" (invocation: "collect_selection ${shellQuote invocation.id} ${invocation.command}") invocations}

    LC_ALL=C sort -u "$collectRoot/manifest.unsorted" > "$collectRoot/manifest.tsv"

    ${lib.optionalString (doctestInvocations != []) ''
      # Doctests compile through rustdoc and cannot be published as
      # executables. Run each doctestable selection once and record the
      # outcome; the runner replays it with each gate's own filters and fails
      # exactly where `cargo test` would have failed.
      mkdir -p "$collectRoot/doctests"
      record_doctests() {
        selection_id=$1
        package=$2
        shift 2
        if ! jq -e --arg package "$package" '
            .packages[] | select(.name == $package) | .targets
            | any((.kind | index("lib") or index("rlib") or index("dylib") or index("proc-macro"))
              and .doctest)
          ' "$collectRoot/metadata.json" > /dev/null; then
          return 0
        fi
        doctest_status=0
        cargo test --doc "$@" -- --test-threads=1 \
          > "$collectRoot/doctests/$selection_id.log" 2>&1 || doctest_status=$?
        cat "$collectRoot/doctests/$selection_id.log"
        printf '%s\n' "$doctest_status" > "$collectRoot/doctests/$selection_id.status"
        sed -n 's/^test \(.*\) \.\.\. \(ok\|ignored\|FAILED\)$/\1\t\2/p' \
          "$collectRoot/doctests/$selection_id.log" \
          | LC_ALL=C sort > "$collectRoot/doctests/$selection_id.tsv"
      }

      ${lib.concatMapStringsSep "\n" (invocation: "record_doctests ${shellQuote invocation.id} ${shellQuote invocation.package} ${invocation.flags}") doctestInvocations}
    ''}

    # Cargo's run-time package environment, quoted for the runner's shell.
    jq -j --arg root "$(cd .. && pwd)/" '
      .packages[]
      | (.manifest_path | ltrimstr($root) | rtrimstr("/Cargo.toml")) as $dir
      | (.version | capture("^(?<major>[0-9]+)[.](?<minor>[0-9]+)[.](?<patch>[0-9]+)(-(?<pre>[^+]*))?")) as $v
      | (.targets | any(
          (.kind | index("lib") or index("rlib") or index("dylib") or index("proc-macro"))
          and .doctest)) as $doctestable
      | [
          "name=\(.name)",
          "CRUCIBLE_CARGO_PACKAGE_DIR=\($dir | @sh)",
          "CRUCIBLE_CARGO_DOCTESTABLE=\(if $doctestable then 1 else 0 end)",
          "CARGO_PKG_NAME=\(.name | @sh)",
          "CARGO_PKG_VERSION=\(.version | @sh)",
          "CARGO_PKG_VERSION_MAJOR=\($v.major | @sh)",
          "CARGO_PKG_VERSION_MINOR=\($v.minor | @sh)",
          "CARGO_PKG_VERSION_PATCH=\($v.patch | @sh)",
          "CARGO_PKG_VERSION_PRE=\(($v.pre // "") | @sh)",
          "CARGO_PKG_AUTHORS=\(.authors | join(":") | @sh)",
          "CARGO_PKG_DESCRIPTION=\((.description // "") | @sh)",
          "CARGO_PKG_HOMEPAGE=\((.homepage // "") | @sh)",
          "CARGO_PKG_REPOSITORY=\((.repository // "") | @sh)",
          "CARGO_PKG_LICENSE=\((.license // "") | @sh)",
          "CARGO_PKG_LICENSE_FILE=\((.license_file // "") | @sh)",
          "CARGO_PKG_RUST_VERSION=\((.rust_version // "") | @sh)",
          "CARGO_PKG_README=\((.readme // "") | @sh)"
        ]
      | join("\n")
      | . + "\n\u0000"
    ' "$collectRoot/metadata.json" \
      | while IFS= read -r -d "" record; do
          package=$(printf '%s' "$record" | sed -n 's/^name=//p')
          printf '%s' "$record" | sed '/^name=/d' > "$collectRoot/packages/$package.env"
        done
  '';

  installCollected = family: profile: ''
    cp -R "$NIX_BUILD_TOP/crucible-workspace-tests/libexec" "$out/libexec"
    cp -R "$NIX_BUILD_TOP/crucible-workspace-tests/packages" "$out/packages"
    cp "$NIX_BUILD_TOP/crucible-workspace-tests/manifest.tsv" "$out/manifest.tsv"
    if [ -d "$NIX_BUILD_TOP/crucible-workspace-tests/doctests" ]; then
      cp -R "$NIX_BUILD_TOP/crucible-workspace-tests/doctests" "$out/doctests"
    fi
    {
      printf 'family=%s\n' ${shellQuote family}
      printf 'profile=%s\n' ${shellQuote profile}
      printf 'source_root=%s\n' "$(cd .. && pwd)"
    } > "$out/build-info"
  '';

  # A family compiles its invocations once against its own dependency
  # artifacts. The artifacts replay identical commands on the dummy source,
  # which keeps their third-party feature resolution exact.
  mkFamily = {
    name,
    profile,
    licenseScope,
    invocations,
    doctestSelections ? [],
  }: let
    doctestInvocations =
      map (selection: {
        id = selectionId selection;
        package = builtins.head selection.packages;
        flags = selectionFlags profile selection;
      })
      doctestSelections;
    commands = lib.unique (map (invocation: invocation.command) invocations);
    contract = {
      family = "crucible-workspace-tests-${name}";
      nativeInputs = map toString nativeBuildDeps;
      inherit licenseScope;
    };
    artifacts = mkCargoArtifacts {
      pname = "crucible-${name}-test-artifacts";
      inherit version cargoDeps cargoEnv;
      cargoArtifactContract = contract;
      src = dummySource;
      cargoRoot = "crates";
      cargoBuildCommands = commands;
      buildDeps = nativeBuildDeps;
      runtimeDeps = nativeRuntimeDeps;
    };
  in
    mkCargoPackage {
      pname = "crucible-${name}-tests";
      inherit version cargoDeps cargoEnv;
      src = buildSource;
      cargoArtifacts = artifacts;
      cargoArtifactContract = contract;
      cargoRoot = "crates";
      cargoBuildCommands = commands;
      buildDeps = nativeBuildDeps;
      runtimeDeps = nativeRuntimeDeps;
      installBins = false;
      doCheck = false;
      # Collection already removed debug sections; keep symbols and Cargo's
      # run paths for gates and flights that copy an executable.
      dontStrip = true;
      dontPatchELF = true;
      postBuild = collectExecutables invocations doctestInvocations;
      postInstall = installCollected name profile;
      passthru = {
        inherit artifacts profile nativeRuntimeDeps;
        family = name;
        selectionIds = lib.unique (map (invocation: invocation.id) invocations);
      };
      meta.description = "Prebuilt Crucible ${name} workspace test executables";
    };

  apacheTests = mkFamily {
    name = "apache-debug";
    profile = "debug";
    licenseScope = "Apache-2.0";
    invocations =
      lib.concatMap (testInvocations "debug") selections.apacheTests
      ++ lib.concatMap (buildInvocations "debug") selections.apacheBuilds;
    doctestSelections = selections.apacheTests;
  };
  gplTests = mkFamily {
    name = "gpl-debug";
    profile = "debug";
    licenseScope = "GPL-2.0-only";
    invocations =
      lib.concatMap (testInvocations "debug") selections.gplTests
      ++ lib.concatMap (buildInvocations "debug") selections.gplBuilds;
    doctestSelections = selections.gplTests;
  };
  apacheRelease = mkFamily {
    name = "apache-release";
    profile = "release";
    licenseScope = "Apache-2.0";
    invocations =
      lib.concatMap (buildInvocations "release") selections.apacheReleaseBuilds
      ++ lib.concatMap (testInvocations "release") selections.apacheReleaseTests;
  };
  gplRelease = mkFamily {
    name = "gpl-release";
    profile = "release";
    licenseScope = "GPL-2.0-only";
    invocations = lib.concatMap (testInvocations "release") selections.gplReleaseTests;
  };
  # Test support changes crucible-qemu's dependency features. Keeping it in
  # its own family leaves the default release executables unaffected.
  apacheReleaseTestSupport = mkFamily {
    name = "apache-release-test-support";
    profile = "release";
    licenseScope = "Apache-2.0";
    invocations = lib.concatMap (buildInvocations "release") selections.apacheReleaseTestSupportBuilds;
  };

  runner = mkDerivation {
    pname = "crucible-cargo";
    inherit version;
    src = null;
    runtimeDeps = [bash coreutils gawk grep sed rust];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          sed \
            -e 's|@bash@|${bash}/bin/bash|' \
            -e 's|@cargo@|${rust}/bin/cargo|' \
            -e 's|@path@|${lib.makeBinPath [coreutils gawk grep sed]}|' \
            ${./crucible-cargo.sh} > "$out/bin/crucible-cargo"
          chmod +x "$out/bin/crucible-cargo"
        '';
      }
    ];
    meta.description = "Runs prebuilt Crucible workspace tests with Cargo's command line";
  };
in {
  inherit apacheTests gplTests apacheRelease apacheReleaseTestSupport gplRelease runner buildSource selections selectionId;
}
