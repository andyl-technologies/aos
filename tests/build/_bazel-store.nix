##! Storage/campaign qualification keeps native imports and feature variants explicit.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/store-inventory.json,
}: let
  store = "//crates/crucible/storage/crucible-store";
  campaign = "//crates/crucible/engine/crucible-campaign";
  packages = {
    crucible-store = "crates/crucible/storage/crucible-store";
    crucible-campaign = "crates/crucible/engine/crucible-campaign";
  };
  nativeLibraries = [pkgs.sqlite];
  nativeTools = [pkgs.pkg-config];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages sourceInventory nativeLibraries nativeTools;
    pname = "aos-bazel-store";
    dependencyProfile = "store";
    # Match the workspace Cargo test profile for campaign scale workloads.
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0"];
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.store // {aos_native = pkgs.aosBazelStoreLibraries;};
    extraSourceDirectories = ["docs/rfcs/0020-crucible-campaigns"];
    excludedTests = ["gate_campaign_store_equivalence" "gate_campaign_mutation_scaling"];
    extraTests = ["${store}:bin_crucible-fleet-store"];
    extraEditorTargets = ["${store}:crucible-fleet-store" "${store}:bin_crucible-fleet-store_binary"];
  };
  variantTargets = suffix: features:
    pkgs.lib.concatMap (name: let
      path = packages.${name};
      label = "//${path}";
      entries = builtins.readDir (../.. + "/${path}/tests");
      integrations = builtins.filter (file:
        entries.${file}
        == "regular"
        && pkgs.lib.hasSuffix ".rs" file
        && (builtins.elem "test-support" features || !(builtins.elem file ["gate_campaign_store_equivalence.rs" "gate_campaign_mutation_scaling.rs"]))) (builtins.attrNames entries);
    in
      map (target: "${label}:${target}${suffix}") (["unit" "doc" "license_closure"] ++ map (pkgs.lib.removeSuffix ".rs") integrations)) (builtins.attrNames packages)
    ++ ["${store}:bin_crucible-fleet-store${suffix}"];
  featureVariant = name: features: let
    suffix = "_${name}";
    tests = pkgs.mkAosBazelCheck {
      pname = "aos-bazel-store-${name}-tests";
      workspace = family.workspace;
      targets = variantTargets suffix features;
    };
    cargo = import ./_bazel-cargo-oracle.nix {
      inherit pkgs nativeLibraries nativeTools;
      pname = "aos-bazel-store-${name}-cargo-oracle";
      packages = builtins.attrNames packages;
      cargoFlags = ["--features" (pkgs.lib.concatStringsSep "," (pkgs.lib.concatMap (package: map (feature: "${package}/${feature}") features) (builtins.attrNames packages)))];
    };
  in
    pkgs.runCommand "aos-bazel-store-${name}-parity" {buildDeps = [pkgs.python3];} ''
      cp ${../../tools/bazel/tests/verify_protocol.py} verify_protocol.py
      cp ${../../tools/bazel/tests/verify_pilot.py} verify_pilot.py
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 verify_protocol.py \
        --tests ${tests}/evidence/tests --inventory ${tests}/inventory.json \
        --messages ${cargo}/cargo-messages.jsonl --cargo-log ${cargo}/cargo-tests.log \
        --package-path crucible-store=crates/crucible/storage/crucible-store \
        --package-path crucible-campaign=crates/crucible/engine/crucible-campaign \
        --target-suffix ${suffix} --output "$out/parity.json"
      cp ${tests}/inventory.json "$out/inventory.json"
    '';
in
  family
  // rec {
    # Only the aspect reports are materialized. Compilation and execution are
    # independently required by the qualification checks below.
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-store-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (variant: variantTargets variant.suffix variant.features) [
          {
            suffix = "";
            features = [];
          }
          {
            suffix = "_test_support";
            features = ["test-support"];
          }
          {
            suffix = "_recovery_faults";
            features = ["destructive-recovery-faults"];
          }
          {
            suffix = "_all_features";
            features = ["test-support" "destructive-recovery-faults"];
          }
        ]
        ++ ["${store}:package"] ++ pkgs.lib.concatMap (label: map (target: "${label}:${target}") ["clippy" "documentation" "format"]) [store campaign];
    };
    build = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-fleet-store";
      workspace = family.workspace;
      targets = ["${store}:package"];
    };
    package = pkgs.mkAosBazelPackage {
      pname = "crucible-fleet-store";
      version = "0.1.0";
      inherit build;
      packageLabel = "${store}:package";
      runtimeDeps = [pkgs.sqlite pkgs.gcc-libs];
    };
    runtime = pkgs.runCommand "aos-bazel-fleet-store-runtime" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${package}/bin/crucible-fleet-store probe "$TMPDIR/store" > "$out/probe.log" 2> "$out/probe.stderr"
      grep -Fx 'backend=SharedDagStore' "$out/probe.log"
      grep -Fx 'location_independent_identity=true' "$out/probe.log"
      grep -Fx 'concurrent_writers=16' "$out/probe.log"
      grep -Fx 'campaign_continuity_prior_findings_reproducible=true' "$out/probe.log"
      if ${package}/bin/crucible-fleet-store aos-invalid-operation > "$out/invalid.log" 2>&1; then
        echo 'fleet-store accepted an unsupported operation' >&2
        exit 1
      else
        printf '%s\n' "$?" > "$out/invalid.status"
      fi
      cp ${package}/nix-support/bazel-package.json "$out/package.json"
      ${pkgs.python3}/bin/python3 - "$out" "$TMPDIR" <<'PYTHON'
      import hashlib
      import json
      from pathlib import Path
      import subprocess
      import sys

      output, temporary = map(Path, sys.argv[1:])
      cargo_binary = Path("${family.cargo}/test-binaries/crucible-fleet-store")
      bazel_binary = Path("${package}/bin/crucible-fleet-store")
      cargo = subprocess.run([str(cargo_binary), "probe", str(temporary / "cargo-store")], capture_output=True, text=True, check=True)
      (output / "cargo-probe.log").write_text(cargo.stdout)
      (output / "cargo-probe.stderr").write_text(cargo.stderr)
      def normalize_probe(log):
          lines = log.splitlines()
          if sum(line.startswith("root=") for line in lines) != 1:
              raise ValueError("store probe omitted its unique storage root")
          return [line for line in lines if not line.startswith("root=")]

      expected = normalize_probe(cargo.stdout)
      if normalize_probe((output / "probe.log").read_text()) != expected or cargo.stderr != (output / "probe.stderr").read_text():
          raise ValueError("installed Bazel and Cargo store probes differ")
      invalid = subprocess.run([str(cargo_binary), "aos-invalid-operation"], capture_output=True, text=True)
      (output / "cargo-invalid.log").write_text(invalid.stdout + invalid.stderr)
      bazel_error = (output / "invalid.log").read_text().replace(str(bazel_binary), "<store>")
      cargo_error = (invalid.stdout + invalid.stderr).replace(str(cargo_binary), "<store>")
      if invalid.returncode != int((output / "invalid.status").read_text()) or cargo_error != bazel_error:
          raise ValueError("installed Bazel and Cargo invalid-command behavior differs")
      (output / "parity.json").write_text(json.dumps({
          "probe_lines": expected,
          "invalid_command_status": invalid.returncode,
          "cargo_binary_sha256": hashlib.sha256(cargo_binary.read_bytes()).hexdigest(),
          "bazel_binary_sha256": hashlib.sha256(bazel_binary.read_bytes()).hexdigest(),
      }, indent=2, sort_keys=True) + "\n")
      PYTHON
    '';
    native-metadata = pkgs.runCommand "aos-bazel-store-native-metadata" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out" ambient
      cat > ambient/aos-undeclared.pc <<'PC'
      Name: aos-undeclared
      Description: An undeclared ambient dependency must remain inaccessible
      Version: 999
      Libs: -lundeclared
      PC
      ${pkgs.python3}/bin/python3 - "$PWD/ambient" "$out/metadata.json" <<'PYTHON'
      import json
      import os
      from pathlib import Path
      import subprocess
      import sys

      repository = Path("${pkgs.aosBazelStoreLibraries}")
      environment = dict(os.environ, PKG_CONFIG_PATH=sys.argv[1], PKG_CONFIG_LIBDIR=sys.argv[1], PKG_CONFIG_SYSROOT_DIR="/ambient")
      selected = {
          "sqlite": ("sqlite3", "${pkgs.sqlite.version}"),
          "zstd": ("libzstd", "${pkgs.zstdStaticMultithread.version}"),
      }
      report = {}
      for name, (module, version) in selected.items():
          wrapper = repository / name / "pkg-config"
          def query(*arguments):
              return subprocess.check_output([str(wrapper), *arguments, module], env=environment, text=True).strip()

          identity = json.loads((repository / name / "closure.json").read_text())
          tools = json.loads((repository / name / "pkg-config-tools.json").read_text())
          if query("--modversion") != version:
              raise ValueError("pkg-config selected an unexpected library version")
          flags = query("--cflags", "--libs", "--static")
          if identity["package"] + "/lib" not in flags or "/ambient" in flags or "//nix/store" in flags:
              raise ValueError("pkg-config did not retain the exact selected Nix library paths")
          rejected = subprocess.run([str(wrapper), "--exists", "aos-undeclared"], env=environment)
          if rejected.returncode == 0:
              raise ValueError("pkg-config accepted an undeclared ambient library")
          report[name] = {"module": module, "version": version, "flags": flags, "library": identity, "tools": tools}
      Path(sys.argv[2]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
      PYTHON
    '';
    variants = {
      test-support = featureVariant "test_support" ["test-support"];
      recovery-faults = featureVariant "recovery_faults" ["destructive-recovery-faults"];
      all-features = featureVariant "all_features" ["test-support" "destructive-recovery-faults"];
    };
    native-linkage =
      pkgs.runCommand "aos-bazel-store-native-linkage" {
        buildDeps = [pkgs.python3];
        outputChecks.out = {};
        exportReferencesGraph.artifact = [package];
      } ''
        cp ${../../tools/bazel/tests/verify_cache.py} verify_cache.py
        cp ${../../tools/bazel/tests/verify_store_native.py} verify_store_native.py
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 verify_store_native.py \
          --build ${build} --package ${package} --libraries ${pkgs.aosBazelStoreLibraries} \
          --readelf ${pkgs.binutils}/bin/readelf --output "$out/linkage.json"
      '';
    all =
      pkgs.runCommand "aos-bazel-store-qualified-checks" {
        buildDeps = [family.all family.editor-parity runtime native-metadata native-linkage] ++ builtins.attrValues variants;
      } ''
        mkdir -p "$out/variants"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp -r ${runtime} "$out/runtime"
        cp ${native-metadata}/metadata.json "$out/native-metadata.json"
        cp ${native-linkage}/linkage.json "$out/native-linkage.json"
        ${pkgs.lib.concatStringsSep "\n" (pkgs.lib.mapAttrsToList (name: variant: ''
            cp ${variant}/parity.json "$out/variants/${name}.json"
          '')
          variants)}
      '';
  }
