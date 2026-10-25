##! Audits live Bazel declarations and default production dependency closures.
{pkgs}: let
  root = ../..;
  packages = [
    "crucible-determinism"
    "crucible-test-support"
    "crucible-qemu-shmem"
    "crucible-qemu-protocol"
    "crucible-device"
    "crucible-engine"
    "crucible-session"
    "crucible-control-api"
    "crucible-daemon"
    "crucible-cli"
    "crucible-qemu-host"
    "crucible-qemu-plugin"
  ];
  productionRoots = builtins.listToAttrs (map (name: {
      inherit name;
      value =
        "//crates/crucible/${name}:"
        + (
          if name == "crucible-cli"
          then "crucible"
          else if name == "crucible-qemu-plugin"
          then "plugin"
          else "lib"
        );
    })
    packages);
  directories = [
    "crates"
    "third_party/rust"
    "tools/bazel/rules"
    "tools/bazel/metadata"
    "tools/bazel/toolchains"
    "tools/bazel/testing"
    "docs/rfcs/0020-crucible-campaigns"
  ];
  paths = directories ++ ["MODULE.bazel" "MODULE.bazel.lock" ".bazelrc"];
  # Audit inputs include integration sources as well as production sources.
  # Exclude Cargo metadata before constructing either the query or build tree.
  source = builtins.path {
    path = root;
    name = "aos-crucible-feature-policy-source";
    filter = path: type: let
      relative = pkgs.lib.removePrefix "${toString root}/" (toString path);
      name = baseNameOf path;
      selected = builtins.any (prefix:
        relative
        == prefix
        || pkgs.lib.hasPrefix "${prefix}/" relative
        || pkgs.lib.hasPrefix "${relative}/" prefix)
      paths;
    in
      toString path
      == toString root
      || (selected && !(builtins.elem name ["Cargo.toml" "Cargo.lock" ".git" ".worktrees" "target" "node_modules" "__pycache__" ".direnv"]));
  };
  workspace = pkgs.mkAosBazelWorkspace {
    # This is an already materialized source path. The workspace copies its
    # selected files; relative filter keys must not inherit its store context.
    root = builtins.unsafeDiscardStringContext (toString source);
    sourceDirectories = directories;
    analysisTargets = builtins.attrValues productionRoots;
    dependencyProfile = "crucible-cli";
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.crucible-cli
      // {
        aos_native = pkgs.aosBazelStoreLibraries;
        aos_qemu_plugin_abi = pkgs.aosBazelQemuPluginAbi;
      };
  };
  roots = builtins.toFile "crucible-production-roots.json" (builtins.toJSON productionRoots);
  featureCases = import ./_bazel-feature-powerset.nix {inherit pkgs;};
  selection = builtins.concatStringsSep " " (map (name: "//crates/crucible/${name}:*") packages);
  query = ''kind("(_source_package|rust_(library|binary|shared_library|test)) rule", set(${selection}))'';
in rec {
  inherit workspace;
  inventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-crucible-production-feature-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
    sharedBuildCache = false;
  };
  all = pkgs.runCommand "aos-bazel-crucible-feature-policy" {buildDeps = [pkgs.python3];} ''
    cp -R ${workspace.source} workspace
    chmod -R u+w workspace
    cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
      --config ${workspace.configuration} --workspace "$PWD/workspace" \
      --output-base "$TMPDIR/bazel" --nix-sandbox -- query --output=xml \
      ${pkgs.lib.escapeShellArg query} > "$out/declarations.xml"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/verify_crucible_feature_policy.py} \
      --root "$PWD/workspace" --roots ${roots} --query "$out/declarations.xml" \
      --inventory ${inventory}/inventory.json \
      --feature-inventory ${featureCases.build}/inventory.json --negative-controls --output "$out/report.json"
    cp ${inventory}/inventory.json "$out/inventory.json"
    printf 'PASS\n' > "$out/result"
  '';
}
