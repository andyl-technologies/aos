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
##! Apache debug tests, GPL-side debug tests, Apache release executables and
##! harnesses, and GPL-side release harnesses. Each family compiles one
##! unified feature resolution plus the few selections whose features would
##! change test behavior (`_workspace-test-selections.nix`), so a source edit
##! recompiles each first-party crate about once per profile. The artifacts
##! derivation replays the same Cargo commands on a manifest-only dummy
##! workspace, so its identity changes only with manifests, the lockfile,
##! the toolchain, and the selection list. Development builds replace that
##! seed with aos-dev's persistent incremental target directory.
##!
##! Each family output contains:
##!
##! ```text
##! build-info                 family, profile, and the compile-time source root
##! aliases.tsv                mode, gate request, target kinds, selection
##! manifest.tsv               selection, role (harness|artifact), kind, name,
##!                            package, path, required-features (or -)
##! packages/<name>.env        Cargo's run-time package environment
##! libexec/<sha>-<name>.zst   content-addressed executables, zstd-compressed;
##!                            cdylibs stay uncompressed for QEMU to load
##! nix-support/executable-references
##!                            the store paths the executables reference
##! doctests/<selection>/<package>.*
##!                            doctest outcomes, replayed with libtest filters
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
  zstd,
}: let
  selections = import ./_workspace-test-selections.nix {inherit lib;};
  buildSource = import ./_cargo-build-source.nix {inherit lib;};
  dummySource = mkCargoDummySource {
    srcRoot = ../../../crates;
    name = "crucible-workspace-tests-dummy-source";
    cargoRoot = "crates";
  };

  nativeBuildDeps = [buildRustDev buildPkgConfig openssl sqlite buildProtobuf];
  nativeRuntimeDeps = [openssl sqlite];

  # Every target kind; a `serves` entry without `kinds` answers all of them.
  allKinds = ["lib" "bin" "test" "bench" "example"];

  selectionFlags = profile: selection:
    lib.concatStringsSep " " (
      ["--frozen" "--offline" "-j$NIX_BUILD_CORES"]
      ++ lib.optional (profile == "release") "--release"
      ++ map (package: "-p ${package}") selection.packages
      ++ lib.optional ((selection.features or []) != [])
      "--features ${lib.concatStringsSep "," selection.features}"
    );

  # One record per Cargo invocation. Invocations of one selection share its
  # feature resolution, so the second compiles only its own targets.
  selectionInvocations = profile: selection:
    map (invocation: {
      inherit (selection) id;
      collect = selection.collect or selection.packages;
      command = lib.concatStringsSep " " (
        [
          (
            if invocation.command == "test"
            then "test --no-run"
            else "build"
          )
          (selectionFlags profile selection)
        ]
        ++ lib.optional (invocation ? cargoProfile) "--profile ${invocation.cargoProfile}"
        ++ invocation.targets
      );
    })
    selection.invocations;

  # Rows of aliases.tsv: mode, request, comma-separated kinds, selection.
  aliasRows = selection:
    lib.concatLists (lib.mapAttrsToList (mode: entries:
      map (entry: let
        request =
          if builtins.isString entry
          then entry
          else entry.request;
        kinds =
          if builtins.isString entry
          then allKinds
          else entry.kinds;
      in {
        inherit mode request kinds;
        inherit (selection) id;
      })
      entries) (selection.serves or {}));

  # A request answered by two selections for the same target kind would be
  # ambiguous; reject the selection list at evaluation instead.
  checkedAliasRows = selections: let
    rows = lib.concatMap aliasRows selections;
    claims = lib.concatMap (row: map (kind: "${row.mode} ${row.request} ${kind}") row.kinds) rows;
    duplicates = lib.subtractLists (lib.unique claims) claims;
  in
    if lib.length (lib.unique claims) == lib.length claims
    then rows
    else throw "crucible workspace tests: ambiguous selections for ${toString duplicates}";

  aliasesFile = name: selections:
    builtins.toFile "crucible-${name}-aliases.tsv" (lib.concatMapStrings (row: "${row.mode}\t${row.request}\t${lib.concatStringsSep "," row.kinds}\t${row.id}\n") (checkedAliasRows selections));

  shellQuote = value: "'${builtins.replaceStrings ["'"] ["'\"'\"'"] value}'";

  # Re-runs each invocation after the build. Every unit is fresh by then, so
  # Cargo only reports the executables of that exact invocation. Cargo also
  # relinks fresh binaries into their uplifted paths, so a binary is copied
  # before the next selection can replace it.
  collectExecutables = invocations: doctestSelections: ''
    collectRoot="$NIX_BUILD_TOP/crucible-workspace-tests"
    mkdir -p "$collectRoot/libexec" "$collectRoot/packages"
    : > "$collectRoot/manifest.unsorted"

    cargo metadata --format-version 1 --frozen --offline --no-deps \
      > "$collectRoot/metadata.json"

    collect_invocation() {
      selection_id=$1
      collect_packages=$2
      shift 2
      cargo "$@" --message-format=json > "$collectRoot/messages.jsonl"
      jq -r --slurpfile metadata "$collectRoot/metadata.json" \
        --arg collect "$collect_packages" '
        ($metadata[0].packages
          | map({key: .manifest_path, value: .name}) | from_entries) as $names
        # Cargo applies required-features per request; the runner needs them
        # to skip targets a narrower request would not have compiled.
        | ($metadata[0].packages
          | map(.manifest_path as $manifest | .targets[]
              | {key: "\($manifest) \(.kind[0]) \(.name)",
                 value: ((."required-features" // []) | join(","))})
          | from_entries) as $required
        | ($collect | split(" ")) as $collected
        | select(.reason == "compiler-artifact")
        # Only workspace targets; build scripts are compiler executables.
        | select($names[.manifest_path] != null)
        | select(.target.kind | index("custom-build") | not)
        # Dependencies of a selection are compiled, not published.
        | $names[.manifest_path] as $package
        | select($collected | index($package))
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
            $package,
            $path,
            ($required["\(.manifest_path) \(.target.kind[0]) \(.target.name)"]
              | if . == null or . == "" then "-" else . end)
          ]
        # A non-whitespace separator keeps empty fields from shifting.
        | join("\u001f")
      ' "$collectRoot/messages.jsonl" > "$collectRoot/artifacts"
      # A selection that publishes nothing means the filter above is wrong.
      test -s "$collectRoot/artifacts"
      while IFS="$(printf '\037')" read -r role kind name package executable required; do
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
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$selection_id" "$role" "$kind" "$name" "$package" "$stored" "$required" \
          >> "$collectRoot/manifest.unsorted"
      done < "$collectRoot/artifacts"
    }

    ${lib.concatMapStringsSep "\n" (invocation: "collect_invocation ${shellQuote invocation.id} ${shellQuote (toString invocation.collect)} ${invocation.command}") invocations}

    LC_ALL=C sort -u "$collectRoot/manifest.unsorted" > "$collectRoot/manifest.tsv"

    ${lib.optionalString (doctestSelections != []) ''
      # Doctests compile through rustdoc and cannot be published as
      # executables. Run them once per selection and record each package's
      # outcome; the runner replays it with each gate's own filters and fails
      # exactly where `cargo test` would have failed. --no-fail-fast keeps one
      # package's failure from hiding the others' results.
      record_doctests() {
        selection_id=$1
        shift
        record="$collectRoot/doctests/$selection_id"
        mkdir -p "$record"
        cargo test --doc --no-fail-fast "$@" -- --test-threads=1 \
          > "$record/all.log" 2>&1 || true
        cat "$record/all.log"

        # Cargo heads each library's doctests with `Doc-tests <crate>`.
        jq -r '
          .packages[] | . as $package | .targets[]
          | select((.kind | index("lib") or index("rlib") or index("dylib") or index("proc-macro"))
              and .doctest)
          | "\($package.name) \(.name)"
        ' "$collectRoot/metadata.json" | while read -r package crate; do
          case " $* " in *" -p $package "*) ;; *) continue ;; esac
          awk -v header="   Doc-tests $crate" '
            $0 == header { inside = 1; next }
            /^   Doc-tests / { inside = 0 }
            inside
          ' "$record/all.log" > "$record/$package.log"
          if grep -q '^test result: ok\.' "$record/$package.log"; then
            printf '0\n' > "$record/$package.status"
          else
            # A missing section means rustdoc failed before running tests.
            [ -s "$record/$package.log" ] || cp "$record/all.log" "$record/$package.log"
            printf '101\n' > "$record/$package.status"
          fi
          sed -n 's/^test \(.*\) \.\.\. \(ok\|ignored\|FAILED\)$/\1\t\2/p' \
            "$record/$package.log" | LC_ALL=C sort > "$record/$package.tsv"
        done
        rm "$record/all.log"
      }

      ${lib.concatMapStringsSep "\n" (selection: "record_doctests ${shellQuote selection.id} ${selection.flags}") doctestSelections}
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

  installCollected = family: profile: aliases: ''
    cp ${aliases} "$out/aliases.tsv"
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

    # Test executables carry literal store paths as fixtures, such as
    # /nix/store/9999...-crucible-qemu-plugin, which the generic reference
    # scrub would rewrite and so change test behavior. Rewrite only paths
    # that exist in this sandbox (real build inputs) and are not runtime
    # dependencies, matching the scrub's keep list.
    keep=" $out ''${buildInputs[*]:-} ''${propagatedBuildInputs[*]:-} ''${nukeRefsKeep[*]:-} "
    scrub_roots=("$out/libexec")
    [ ! -d "$out/doctests" ] || scrub_roots+=("$out/doctests")
    find "''${scrub_roots[@]}" -type f | while read -r file; do
      { grep -aoE '/nix/store/[0-9a-z]{32}-' "$file" || true; } | LC_ALL=C sort -u \
        | while read -r prefix; do
            hash=''${prefix#/nix/store/}
            hash=''${hash%-}
            set -- /nix/store/"$hash"-*
            [ -e "$1" ] || continue
            case $keep in *" $1 "*) continue ;; esac
            chmod u+w "$file"
            LC_ALL=C sed -i "s|/nix/store/$hash-|/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-|g" "$file"
          done
    done

    # Test executables are most of a family and compress about fivefold;
    # the runner decompresses each into the gate's writable copy, which it
    # makes anyway. Compression hides store paths from Nix's reference
    # scan, so the paths that exist (run-time libraries, not fixtures) are
    # recorded in plain text first.
    mkdir -p "$out/nix-support"
    find "$out/libexec" -type f -exec grep -aohE '/nix/store/[0-9a-z]{32}-[^/[:space:][:cntrl:]"]+' {} + \
      | LC_ALL=C sort -u | while read -r reference; do
          [ ! -e "$reference" ] || printf '%s\n' "$reference"
        done > "$out/nix-support/executable-references"
    find "$out/libexec" -type f ! -name '*.so' -print0 \
      | xargs -0 -r -n 8 -P "$NIX_BUILD_CORES" ${zstd}/bin/zstd -q -9 -T1 --rm
    awk -F '\t' 'BEGIN { OFS = "\t" } $6 !~ /[.]so$/ { $6 = $6 ".zst" } { print }' \
      "$out/manifest.tsv" > "$out/manifest.tsv.new"
    mv "$out/manifest.tsv.new" "$out/manifest.tsv"
  '';

  # A family compiles its selections once against its own dependency
  # artifacts. The artifacts replay identical commands on the dummy source,
  # which keeps their third-party feature resolution exact.
  mkFamily = {
    name,
    profile,
    licenseScope,
    familySelections,
  }: let
    invocations = lib.concatMap (selectionInvocations profile) familySelections;
    doctestSelections =
      map (selection: {
        inherit (selection) id;
        flags = selectionFlags profile selection;
      })
      (lib.filter (selection: selection.doctests or false) familySelections);
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
      # installCollected removes build-only references itself; see there.
      dontNukeRefs = true;
      postBuild = collectExecutables invocations doctestSelections;
      postInstall = installCollected name profile (aliasesFile name familySelections);
      passthru = {
        inherit artifacts profile nativeRuntimeDeps;
        family = name;
        selectionIds = map (selection: selection.id) familySelections;
      };
      meta.description = "Prebuilt Crucible ${name} workspace test executables";
    };

  apacheTests = mkFamily {
    name = "apache-debug";
    profile = "debug";
    licenseScope = "Apache-2.0";
    familySelections = selections.apacheTests;
  };

  gplTests = mkFamily {
    name = "gpl-debug";
    profile = "debug";
    licenseScope = "GPL-2.0-only";
    familySelections = selections.gplTests;
  };

  apacheRelease = mkFamily {
    name = "apache-release";
    profile = "release";
    licenseScope = "Apache-2.0";
    familySelections = selections.apacheRelease;
  };

  gplRelease = mkFamily {
    name = "gpl-release";
    profile = "release";
    licenseScope = "GPL-2.0-only";
    familySelections = selections.gplRelease;
  };

  runner = mkDerivation {
    pname = "crucible-cargo";
    inherit version;
    src = null;
    runtimeDeps = [bash coreutils gawk grep sed zstd rust];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          sed \
            -e 's|@bash@|${bash}/bin/bash|' \
            -e 's|@cargo@|${rust}/bin/cargo|' \
            -e 's|@path@|${lib.makeBinPath [coreutils gawk grep sed zstd]}|' \
            ${./crucible-cargo.sh} > "$out/bin/crucible-cargo"
          chmod +x "$out/bin/crucible-cargo"
        '';
      }
    ];
    meta.description = "Runs prebuilt Crucible workspace tests with Cargo's command line";
  };
in {
  inherit apacheTests gplTests apacheRelease gplRelease runner buildSource selections;
}
