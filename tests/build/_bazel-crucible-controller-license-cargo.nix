##! Retains the independent Cargo license audit with its explicit source fixtures.
{pkgs}: let
  patches = ../../pkgs/emulation/qemu-patches;
  extraPaths =
    [
      "AGENTS.md"
      "CONTRIBUTING.md"
      "README.md"
      "LICENSES/Apache-2.0.txt"
      "LICENSES/MIT.txt"
      "LICENSES/GPL-2.0-only.txt"
      "LICENSES/GPL-2.0-or-later.txt"
      "docs/legal/licensing.md"
      "docs/legal/external-contributor-license-agreement.md"
      "docs/maintainers/contributor-licensing.md"
      "docs/maintainers/README.md"
      "pkgs/emulation/crucible-qemu-plugin.nix"
      "pkgs/emulation/_crucible-qemu-bazel-installed.nix"
      "pkgs/tools/crucible/_debug-gateway.nix"
    ]
    ++ map (name: "pkgs/emulation/qemu-patches/" + name)
    (builtins.filter (name: name == "LICENSES.md" || pkgs.lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patches)));
in
  import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-crucible-controller-license-cargo-oracle";
    packages = ["crucible-test-support"];
    cargoFlags = ["--test" "gate_license_boundary"];
    captureCompilerArguments = true;
    cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {
      inherit (pkgs) lib;
      inherit extraPaths;
    };
  }
