##! Compares independent controller production graphs before public integration.
{pkgs}: let
  sourceInventories = {
    cli = ../../tools/bazel/metadata/crucible-controller-cli-inventory.json;
    debugger = ../../tools/bazel/metadata/crucible-controller-debugger-inventory.json;
    scenario = ../../tools/bazel/metadata/crucible-controller-scenario-inventory.json;
  };
  strict = pkgs.callPackage ../../pkgs/tools/crucible/_controller-bazel-build.nix {inherit sourceInventories;};
  broad = pkgs.callPackage ../../pkgs/tools/crucible/_controller-bazel-build.nix {};
  cargo = import ./_bazel-crucible-controller-cargo.nix {inherit pkgs;};
  packages =
    builtins.filter (name: !builtins.elem name ["crucible-qemu-plugin" "crucible-qemu-debug-gateway"])
    (import ../../pkgs/tools/crucible/_packages.nix);
  packagePaths = builtins.listToAttrs (map (name: {
      inherit name;
      value =
        if name == "aos-linux-project-quota"
        then "crates/linux/${name}"
        else "crates/crucible/${name}";
    })
    packages);
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-controller-artifact-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
in
  pkgs.runCommand "aos-bazel-crucible-controller-artifact-parity" {
    buildDeps = [pkgs.python3 pkgs.binutils];
    outputChecks.out = {};
  } ''
    mkdir -p "$out"
    cat > contexts.json <<'JSON'
    ${builtins.toJSON (builtins.mapAttrs (name: context: {
        build = toString context.build;
        broad_build = toString broad.${name}.build;
        workspace = toString context.workspace.source;
        source_inventory = "${sourceInventories.${name}}";
      })
      strict)}
    JSON
    cat > package-paths.json <<'JSON'
    ${builtins.toJSON packagePaths}
    JSON
    PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_crucible_controller_artifacts.py \
      --contexts contexts.json --package-paths package-paths.json --cargo ${cargo} \
      --readelf ${pkgs.binutils}/bin/readelf \
      --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
      --output "$out/report.json"
    printf 'PASS\n' > "$out/result"
  ''
