##! Qualifies the Linux quota family on an explicit foreign Linux target.
{pkgs}: let
  native = import ./_bazel-quota.nix {inherit pkgs;};
  targetPackages = (import ../.. {crossSystem = "aarch64-linux";}).pkgs;
  toolchains = pkgs.mkAosBazelCrossToolchains {inherit targetPackages;};
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit toolchains;
    sourceInventory = ../../tools/bazel/metadata/quota-inventory.json;
    dependencyProfile = "quota";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.quota;
    targetPlatform = "//tools/bazel/toolchains:aarch64_linux";
    compileOnly = true;
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/linux/aos-linux-project-quota:unit"];
  };
  inventory = builtins.fromJSON (builtins.readFile ../../tools/bazel/metadata/quota-inventory.json);
  targets = map (target: target.label) (builtins.filter
    (target: target.kind == "rust_test")
    inventory.configured_targets);
  compilation =
    pkgs.runCommand "aos-bazel-quota-aarch64-compilation" {
      buildDeps = [pkgs.python3];
      outputs = ["out" "evidence"];
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
    } ''
      mkdir workspace tools
      cp -a ${workspace.source}/. workspace/
      chmod -R u+w workspace
      cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
      cp ${../../tools/bazel/tests/family_libtest.py} tools/family_libtest.py
      cp ${../../tools/bazel/tests/verify_cache.py} tools/verify_cache.py
      cp ${../../tools/bazel/tests/verify_cross_linux.py} tools/verify_cross_linux.py
      cp ${../../tools/bazel/tests/verify_family_cross.py} tools/verify_family_cross.py
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
        --config ${workspace.configuration} --workspace "$PWD/workspace" \
        --output-base "$TMPDIR/bazel" --nix-sandbox --batch \
        -- build ${pkgs.lib.escapeShellArgs targets} \
        --materialize_param_files \
        --build_event_json_file="$TMPDIR/events.json" \
        --execution_log_json_file="$TMPDIR/execution.json"
      ${pkgs.python3}/bin/python3 tools/verify_family_cross.py \
        --workspace "$PWD/workspace" --events "$TMPDIR/events.json" \
        --execution "$TMPDIR/execution.json" --parity ${native.oracle}/parity.json \
        --output "$out" --evidence "$evidence"
      cp "$TMPDIR/events.json" "$evidence/evidence/events.json"
    '';
  runtime = import ./_bazel-family-vm.nix {
    inherit pkgs targetPackages compilation;
    pname = "aos-bazel-quota-aarch64";
    source = workspace.source;
  };
in
  runtime // {inherit compilation;}
