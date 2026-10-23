##! Keeps configuration libraries independent of their installed command closure.
{
  pkgs,
  sourceInventory,
}: let
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    dependencyProfile = "boot-preparation";
    # A package-runtime builder must be able to compile this library without
    # requesting the package-runtime output embedded only by boot commands.
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.boot-preparation;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) [
      "tools/bazel"
      "third_party/rust"
      "crates/shared/aos-artifact-evidence"
      "crates/shared/aos-core"
      "crates/aos/activation/aos-activation"
      "crates/aos/modules/aos-module-format"
      "crates/aos/boot/aos-configuration-image"
    ];
    analysisTargets = ["//crates/aos/boot/aos-configuration-image:lib"];
  };
  library = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-configuration-library-without-boot-tools";
    inherit workspace;
    targets = workspace.selectedTargets;
  };
in
  pkgs.runCommand "aos-bazel-boot-library-command-boundary" {
    buildDeps = [pkgs.python3 library];
  } ''
    mkdir workspace
    cp -a ${workspace.source}/. workspace/
    chmod -R u+w workspace
    cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
    mkdir -p "$out"
    if ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
      --config ${workspace.configuration} --workspace "$PWD/workspace" \
      --output-base "$TMPDIR/command/bazel" --nix-sandbox --batch \
      -- build //crates/aos/boot/aos-configuration-image:aos-configuration-boot \
      > "$out/missing-command-tools.log" 2>&1; then
      echo "boot command accepted an undeclared command-tool repository" >&2
      exit 1
    fi
    grep -F 'aos_boot_tools' "$out/missing-command-tools.log"
    grep -F 'must be supplied by Nix' "$out/missing-command-tools.log"
    cp ${library}/inventory.json "$out/library-inventory.json"
    cp ${library}/evidence/execution.json "$out/library-execution.json"
    cat > "$out/report.json" <<'REPORT'
    {"library_without_command_tools":"PASS","command_without_command_tools":"REJECTED"}
    REPORT
  ''
