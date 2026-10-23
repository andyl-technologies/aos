##! Qualification entry points for the first-party Bazel migration.
{
  pkgs,
  sharedBazelCacheDir ? null,
}: let
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "tools/bazel/tests/fixture"];
  };
  # Only the temporary parity check reads these manifests. They never enter
  # the Bazel workspace or its compilation inputs.
  metadataOracle = builtins.path {
    path = ../..;
    name = "aos-bazel-package-metadata-oracle";
    filter = path: _type: let
      relative = pkgs.lib.removePrefix "${toString ../..}/" (toString path);
      manifests = [
        "crates/Cargo.toml"
        "crates/aos/boot/aos-boot-identity/Cargo.toml"
        "crates/aos/boot/aos-recovery/Cargo.toml"
        "crates/shared/aos-core/Cargo.toml"
        "crates/shared/aos-artifact-evidence/Cargo.toml"
        "crates/shared/aos-oci-types/Cargo.toml"
        "crates/crucible/qemu/crucible-qemu-host/Cargo.toml"
        "crates/crucible/control/crucible-control-client/Cargo.toml"
        "crates/crucible/control/crucible-control-server/Cargo.toml"
        "crates/crucible/control/crucible-session/Cargo.toml"
        "crates/crucible/control/crucible-control-api/Cargo.toml"
        "crates/shared/aos-linux-project-quota/Cargo.toml"
        "crates/crucible/engine/crucible-determinism/Cargo.toml"
        "crates/crucible/engine/crucible-device/Cargo.toml"
        "crates/crucible/engine/crucible-campaign/Cargo.toml"
        "crates/crucible/engine/crucible-engine/Cargo.toml"
        "crates/crucible/guest/crucible-guest/Cargo.toml"
        "crates/crucible/storage/crucible-store/Cargo.toml"
        "crates/crucible/protocol/crucible-qemu-protocol/Cargo.toml"
        "crates/crucible/protocol/crucible-qemu-shmem/Cargo.toml"
        "crates/crucible/testing/crucible-test-support/Cargo.toml"
      ];
    in
      toString path
      == toString ../..
      || builtins.any (name: relative == name || pkgs.lib.hasPrefix "${relative}/" name) manifests;
  };
in
  rec {
    source-selection = import ./_bazel-source-selection.nix {inherit pkgs;};
    source-catalog = import ./_bazel-source-catalog.nix {inherit pkgs;};
    sysroot-metadata = import ./_bazel-sysroot-metadata.nix {inherit pkgs;};
    manifest-extractor = import ./_bazel-manifest-extractor.nix {inherit pkgs;};
    static-runtime = import ./_bazel-static-runtime.nix {inherit pkgs;};
    native-libraries = let
      shared = import ./_bazel-native-libraries.nix {inherit pkgs;};
      static = import ./_bazel-native-libraries.nix {
        inherit pkgs;
        linkage = "static";
      };
    in
      (pkgs.runCommand "aos-bazel-native-library-checks" {buildDeps = [shared static];} ''
        mkdir -p "$out"
        cp ${shared}/evidence/native-libraries.json "$out/shared.json"
        cp ${static}/evidence/native-libraries.json "$out/static.json"
        printf 'PASS\n' > "$out/result"
      '')
      // {inherit shared static;};
    pilot = import ./_bazel-pilot.nix {inherit pkgs;};
    dependencies = import ./_bazel-dependencies.nix {inherit pkgs;};
    protocol = import ./_bazel-protocol.nix {inherit pkgs;};
    shared = import ./_bazel-shared.nix {inherit pkgs;};
    device = import ./_bazel-device.nix {inherit pkgs;};
    store = import ./_bazel-store.nix {inherit pkgs;};
    guest = import ./_bazel-guest.nix {inherit pkgs;};
    engine = import ./_bazel-engine.nix {inherit pkgs;};
    quota = import ./_bazel-quota.nix {inherit pkgs;};
    session = import ./_bazel-session.nix {inherit pkgs;};
    control = import ./_bazel-control.nix {inherit pkgs;};
    qemu-host = import ./_bazel-qemu-host.nix {inherit pkgs;};
    wasm = import ./_bazel-wasm.nix {inherit pkgs;};
    recovery = import ./_bazel-recovery.nix {inherit pkgs;};
    license-boundary = import ./_bazel-license.nix {inherit pkgs workspace;};
    precise = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-precise-fixtures";
      workspace = pkgs.mkAosBazelWorkspace {
        root = ../..;
        sourceInventory = ../../tools/bazel/metadata/fixture-inventory.json;
      };
      targets = ["//tools/bazel/tests/fixture:package"];
    };
    precision-parity = pkgs.runCommand "aos-bazel-source-precision-parity" {} ''
      cmp ${fixtures}/packages/index.json ${precise}/packages/index.json
      for manifest in ${fixtures}/packages/*/manifest.json; do
        relative="''${manifest#${fixtures}/}"
        cmp "$manifest" "${precise}/$relative"
      done
      mkdir -p "$out"
      cp ${precise}/inventory.json "$out/inventory.json"
    '';
    toolchains = pkgs.aosBazelToolchains;
    shell-bootstrap = pkgs.runCommand "aos-bazel-bootstrap-shell-policy" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 - ${pkgs.aosBazelModules.rules_rust} "$out" <<'PYTHON'
      import json
      from pathlib import Path
      import sys

      root = Path(sys.argv[1])
      bootstrap = root / "util/process_wrapper/private/process_wrapper.sh"
      assert bootstrap.read_text().splitlines()[0] == "#!${pkgs.bash}/bin/bash"
      writer = root / "rust/private/rustdoc/rustdoc_test_writer.rs"
      assert "#!${pkgs.bash}/bin/bash" in writer.read_text()
      assert "#!/usr/bin/env bash" not in writer.read_text()
      (Path(sys.argv[2]) / "evidence.json").write_text(json.dumps({
          "compatibility_bin_sh_present": Path("/bin/sh").exists(),
          "bootstrap_interpreter": bootstrap.read_text().splitlines()[0],
      }, indent=2, sort_keys=True) + "\n")
      PYTHON
      printf 'PASS\n' > "$out/result"
    '';
    fixtures = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-fixtures";
      inherit workspace;
      targets = ["//tools/bazel/tests/fixture:package"];
    };
    package = pkgs.mkAosBazelPackage {
      pname = "aos-bazel-fixture";
      version = "1.2.3-rc.4+local.5";
      build = fixtures;
      packageLabel = "//tools/bazel/tests/fixture:package";
      runtimeDeps = [pkgs.gcc-libs];
    };
    runtime = pkgs.runCommand "aos-bazel-fixture-runtime" {} ''
      test "$(${package}/bin/rust-fixture)" = 'answer=42'
      test "$(${package}/bin/cpp-fixture)" = 'answer=42'
      test "$(${package}/bin/native-fixture)" = 'answer=84'
      mkdir -p "$out"
      cp ${package}/nix-support/bazel-package.json "$out/manifest.json"
    '';
    unit = pkgs.mkAosBazelCheck {
      pname = "aos-bazel-fixture-unit";
      inherit workspace;
      targets = ["//tools/bazel/tests/fixture:rust_test"];
    };
    developer-build = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-developer-tools";
      inherit workspace;
      targets = ["//tools/bazel/tests/fixture:clippy" "//tools/bazel/tests/fixture:documentation" "//tools/bazel/tests/fixture:analyzer_toolchain"];
    };
    developer-tests = pkgs.mkAosBazelCheck {
      pname = "aos-bazel-developer-tests";
      inherit workspace;
      targets = ["//tools/bazel/tests/fixture:format" "//tools/bazel/tests/fixture:doctest"];
    };
    editor = pkgs.runCommand "aos-bazel-editor-check" {buildDeps = [pkgs.python3];} ''
      mkdir workspace
      cp -a ${workspace.source}/. workspace/
      chmod -R u+w workspace
      cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
        --config ${workspace.configuration} --workspace "$PWD/workspace" \
        --output-base "$TMPDIR/editor/bazel" --nix-sandbox --batch \
        --rust-project-output "$PWD/rust-project.json" \
        -- build //tools/bazel/tests/fixture:rust_app //tools/bazel/tests/fixture:native_app //tools/bazel/tests/fixture:rust_test_binary
      ${pkgs.python3}/bin/python3 - "$PWD/rust-project.json" <<'PYTHON'
      import json
      from pathlib import Path
      import sys

      project = json.loads(Path(sys.argv[1]).read_text())
      crates = {item["display_name"]: item for item in project["crates"]}
      assert "fixture_generated" in crates and "fixture_macro" in crates, crates.keys()
      for crate in crates.values():
          assert Path(crate["root_module"]).is_file(), crate
          if crate["is_proc_macro"]:
              assert Path(crate["proc_macro_dylib_path"]).is_file(), crate
      assert Path(project["sysroot_src"], "core/src/lib.rs").is_file(), project
      PYTHON
      # Only prepared upstream-library metadata is available through CARGO.
      # Generated first-party source and proc macros come from Bazel above.
      CARGO=${workspace.toolchains}/bin/cargo \
        RUSTC=${workspace.toolchains}/bin/rustc RAYON_NUM_THREADS=4 \
        ${workspace.toolchains}/developer/bin/rust-analyzer analysis-stats "$PWD" \
          --disable-build-scripts \
          --proc-macro-srv ${workspace.toolchains}/developer/bin/proc-macro-srv \
          > "$out/analysis.log" 2>&1
      ${pkgs.python3}/bin/python3 - "$out/analysis.log" <<'PYTHON'
      from pathlib import Path
      import re
      import sys

      log = Path(sys.argv[1]).read_text()
      for category in ["exprs", "pats"]:
          assert re.search(rf"{category}: [0-9]+, \?\?ty: 0 \(0%\), \?ty: 0 \(0%\)", log), log
      assert "panics: 0" in log and "proc_macros: 1" in log, log
      PYTHON
      cp rust-project.json "$out/rust-project.json"
    '';
    developer-evidence = pkgs.runCommand "aos-bazel-developer-evidence" {buildDeps = [pkgs.python3 developer-build];} ''
      ${pkgs.python3}/bin/python3 - ${developer-tests}/evidence/tests <<'PYTHON'
      import json
      from pathlib import Path
      import sys

      root = Path(sys.argv[1])
      results = json.loads((root / "index.json").read_text())["results"]
      assert len(results) == 2 and all(item["status"] == "PASSED" for item in results), results
      docs = [item for item in results if item["identity"]["label"].endswith(":doctest")]
      assert len(docs) == 1, results
      log = (root / docs[0]["outputs"]["test.log"]).read_text()
      assert "1 passed; 0 failed; 0 ignored" in log, log
      PYTHON
      mkdir -p "$out"
      cp -r ${developer-tests}/evidence/tests "$out/tests"
    '';
    developer-policy = pkgs.runCommand "aos-bazel-developer-policy" {buildDeps = [pkgs.python3];} ''
      cmp ${../../crates/clippy.toml} ${../../tools/bazel/rules/clippy.toml}
      ${pkgs.python3}/bin/python3 - ${../../crates/Cargo.toml} ${../../tools/bazel/rules/BUILD.bazel} <<'PYTHON'
      import ast
      from pathlib import Path
      import re
      import sys
      import tomllib

      cargo = tomllib.loads(Path(sys.argv[1]).read_text())["workspace"]["lints"]["clippy"]
      declaration = Path(sys.argv[2]).read_text()
      clippy = ast.literal_eval(re.search(r"clippy = (\{[^}]+\})", declaration).group(1))
      assert clippy == cargo, (clippy, cargo)
      PYTHON
      mkdir workspace
      cp -a ${workspace.source}/. workspace/
      chmod -R u+w workspace
      cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
      mkdir -p "$out"
      for target in host_clock unwrap; do
        if ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
          --config ${workspace.configuration} --workspace "$PWD/workspace" \
          --output-base "$TMPDIR/$target/bazel" --nix-sandbox --batch \
          -- build "//tools/bazel/tests/fixture/lint_negative:''${target}_check" \
          > "$out/$target.log" 2>&1; then
          echo "workspace Clippy violation was accepted: $target" >&2
          exit 1
        fi
      done
      grep -F 'host monotonic time must not enter Crucible state paths' "$out/host_clock.log"
      grep -E 'clippy::unwrap[_-]used' "$out/unwrap.log"
    '';
    metadata-policy = pkgs.runCommand "aos-bazel-package-metadata-policy" {buildDeps = [pkgs.python3];} ''
      mkdir workspace
      cp -a ${workspace.source}/. workspace/
      chmod -R u+w workspace
      cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/verify_metadata_rejections.py} \
        --workspace "$PWD/workspace" --launcher ${../../tools/bazel/launcher.py} \
        --config ${workspace.configuration} --output-base "$TMPDIR/metadata/bazel" --output "$out"
    '';
    metadata-parity = pkgs.runCommand "aos-bazel-package-metadata-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/verify_package_metadata.py} \
        --root ${metadataOracle} --inventory ${pilot.build}/inventory.json \
        --inventory ${pilot.unit}/inventory.json --inventory ${protocol.tests}/inventory.json \
        --inventory ${dependencies.core}/inventory.json --inventory ${shared.tests}/inventory.json \
        --inventory ${device.tests}/inventory.json --inventory ${store.tests}/inventory.json \
        --inventory ${guest.tests}/inventory.json \
        --inventory ${engine.tests}/inventory.json \
        --inventory ${quota.tests}/inventory.json \
        --inventory ${session.tests}/inventory.json \
        --inventory ${control.tests}/inventory.json \
        --inventory ${qemu-host.tests}/inventory.json \
        --output "$out/parity.json"
    '';
    runner = pkgs.runCommand "aos-bazel-runner-evidence" {buildDeps = [pkgs.python3];} ''
      ${pkgs.python3}/bin/python3 - ${unit}/evidence/tests <<'PY'
      import json
      from pathlib import Path
      import sys
      import xml.etree.ElementTree as ET

      root = Path(sys.argv[1])
      results = json.loads((root / "index.json").read_text())["results"]
      assert len(results) == 1 and results[0]["status"] == "PASSED", results
      cases = ET.parse(root / results[0]["outputs"]["test.xml"]).findall("testcase")
      assert len(cases) == 4, [case.attrib for case in cases]
      assert not any(case.find("failure") is not None for case in cases)
      PY
      mkdir -p "$out"
      cp -r ${unit}/evidence/tests "$out/tests"
    '';
    policy =
      pkgs.runCommand "aos-bazel-policy-checks" {
        buildDeps = [pkgs.python3];
        src = builtins.path {
          path = ../../tools/bazel;
          name = "aos-bazel-policy-tests";
          filter = path: type:
            type
            == "directory"
            && baseNameOf path != "__pycache__"
            || pkgs.lib.hasSuffix ".py" (baseNameOf path);
        };
      } ''
        ${pkgs.python3}/bin/python3 ${../../tools/bazel/metadata/test_policy.py} \
          --oracle ${../../crates/.config/nextest.toml} \
          --output ${../../tools/bazel/testing/policy.json} --check
        PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 -m unittest discover \
          -s "$src/tests" -p 'test_*.py'
        mkdir -p "$out"
        printf 'PASS\n' > "$out/result"
      '';
    all =
      pkgs.runCommand "aos-bazel-checks" {
        buildDeps =
          [runtime runner editor developer-evidence developer-policy metadata-policy metadata-parity policy shell-bootstrap source-selection source-catalog.all sysroot-metadata manifest-extractor native-libraries static-runtime.all precision-parity license-boundary pilot.all dependencies.all protocol.all shared.all device.all store.all guest.all engine.all quota.all session.all control.all qemu-host.all wasm.all recovery]
          ++ pkgs.lib.optionals (pkgs.stdenv.hostPlatform.isLinux && pkgs.stdenv.hostPlatform.isx86_64) [
            (import ./_bazel-cross-linux.nix {inherit pkgs;}).all
            (import ./_bazel-device-cross.nix {inherit pkgs;})
            (import ./_bazel-quota-cross.nix {inherit pkgs;})
            (import ./_bazel-session-cross.nix {inherit pkgs;})
            (import ./_bazel-control-cross.nix {inherit pkgs;})
            (import ./_bazel-qemu-host-cross.nix {inherit pkgs;})
          ];
      } ''
        mkdir -p "$out"
        printf 'PASS\n' > "$out/result"
      '';
  }
  // pkgs.lib.optionalAttrs (pkgs.stdenv.hostPlatform.isLinux && pkgs.stdenv.hostPlatform.isx86_64) {
    cross-linux = import ./_bazel-cross-linux.nix {inherit pkgs;};
    cross-device = import ./_bazel-device-cross.nix {inherit pkgs;};
    cross-quota = import ./_bazel-quota-cross.nix {inherit pkgs;};
    cross-session = import ./_bazel-session-cross.nix {inherit pkgs;};
    cross-control = import ./_bazel-control-cross.nix {inherit pkgs;};
    cross-qemu-host = import ./_bazel-qemu-host-cross.nix {inherit pkgs;};
  }
  // pkgs.lib.optionalAttrs (sharedBazelCacheDir != null) {
    cache = import ./_bazel-cache.nix {inherit pkgs workspace;};
  }
