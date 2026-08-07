{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleWorkspacePackage",
  taskIds ? ["T-PKG-8"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};

  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  cruciblePackageNix = builtins.readFile ../../pkgs/tools/crucible/crucible.nix;
  packageInventory = import ../../pkgs/tools/crucible/_packages.nix;
  workspaceManifest = builtins.fromTOML (builtins.readFile ../../crates/Cargo.toml);
  defaultChecks = builtins.readFile ./default.nix;

  workspaceMembers = workspaceManifest.workspace.members;
  crucibleWorkspaceMembers = builtins.filter (member: lib.hasPrefix "crucible" member) workspaceMembers;
  missingInventoryMembers =
    builtins.filter (member: !(builtins.elem member packageInventory)) crucibleWorkspaceMembers;
  extraInventoryMembers =
    builtins.filter (member: !(builtins.elem member workspaceMembers)) packageInventory;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  inventoryFailures =
    map (member: "pkgs/tools/crucible/_packages.nix: missing Crucible workspace member `${member}`")
    missingInventoryMembers
    ++ map (member: "pkgs/tools/crucible/_packages.nix: member `${member}` is not in crates/Cargo.toml")
    extraInventoryMembers;

  failures =
    failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-8 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleWorkspacePackage`";
      }
      {
        label = "workspace-scoped cargo test wording";
        needle = "workspace-scoped Cargo test suite";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible/crucible.nix" cruciblePackageNix [
      {
        label = "AOS cargo package builder";
        needle = "mkCargoPackage {";
      }
      {
        label = "vendored cargo deps";
        needle = "cargoDeps = fetchCargoDeps";
      }
      {
        label = "pinned vendored dependency hash binding";
        needle = "cargoDepsHash = \"sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=\";";
      }
      {
        label = "vendored dependency hash consumed by cargo deps";
        needle = "hash = cargoDepsHash;";
      }
      {
        label = "non-Crucible workspace excludes";
        needle = "nonCrucibleWorkspacePackages = [";
      }
      {
        label = "workspace cargo flags";
        needle = "workspaceCargoFlags = builtins.concatStringsSep \" \"";
      }
      {
        label = "workspace cargo build";
        needle = "cargoFlags = workspaceCargoFlags;";
      }
      {
        label = "workspace cargo test";
        needle = "cargoTestFlags = \"" + "$" + "{workspaceCargoFlags} --features crucible-cli/test-double\";";
      }
      {
        label = "package checks enabled";
        needle = "doCheck = true;";
      }
      {
        label = "clippy checks in package build";
        needle = "cargo clippy";
      }
      {
        label = "docs warning gate";
        needle = "RUSTDOCFLAGS=\"-D warnings -D missing_docs\"";
      }
      {
        label = "doctests run hermetically";
        needle = "cargo test \\\n        --doc";
      }
      {
        label = "suite runtime closure co-retains controller/QEMU/plugin/source/kernel/fixtures";
        needle = "[controller debugGateway qemu-crucible crucible-qemu-plugin qemu-crucible-source linux-crucible crucible-fixtures gdb openssh coreutils grep sed util-linux]";
      }
      {
        label = "suite is the aggregate release root";
        needle = "artifact_role=aggregate-release-root";
      }
      {
        label = "suite exposes packaged SSH";
        needle = "ln -s " + "$" + "{openssh}/bin/ssh \"$out/bin/ssh\"";
      }
      {
        label = "suite exposes manual live debugger matrix";
        needle = ''$out/bin/crucible-debugger-live-matrix'';
      }
      {
        label = "suite release root names corresponding source";
        needle = "pair_1_corresponding_source_path=" + "$" + "{qemu-crucible-source}";
      }
      {
        label = "suite installs the MIT boundary-crate notice";
        needle = "cp " + "$" + "{../../../LICENSES/MIT.txt} \"$out/share/licenses/crucible/MIT.txt\"";
      }
      {
        label = "suite build info inventories every project component license";
        needle = "component_licenses=Apache-2.0,MIT,GPL-2.0-only,GPL-2.0-or-later";
      }
      {
        label = "suite build info names the MIT boundary crates";
        needle = "boundary_crates=crucible-protocol,crucible-shmem";
      }
      {
        label = "suite metadata inventories every project component license";
        needle = "license = [\"Apache-2.0\" \"MIT\" \"GPL-2.0-only\" \"GPL-2.0-or-later\" \"GPL-3.0-or-later\" \"BSD-2-Clause\"];";
      }
      {
        label = "workspace build info";
        needle = "cargo_workspace_flags=" + "$" + "{workspaceCargoFlags}";
      }
    ]
    ++ forbiddenFor "pkgs/tools/crucible/crucible.nix" cruciblePackageNix [
      {
        label = "host cargo path";
        needle = "/usr/bin/env cargo";
      }
      {
        label = "host shell path";
        needle = "/bin/sh";
      }
      {
        label = "nixpkgs import";
        needle = "<nixpkgs>";
      }
      {
        label = "hostTools pattern";
        needle = "hostTools";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 package check imported";
        needle = "crucibleWorkspacePackage = import ./phase7-crucible-workspace-package.nix";
      }
    ]
    ++ inventoryFailures;
in
  if failures != []
  then throw "crucible phase7 workspace package check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-crucible-workspace-package";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
      ];

      passthru.cruciblePackage = pkgs.crucible;

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            package=crucible
            package_passthru=pkgs.crucible
            build_system=mkCargoPackage
            cargo_deps=fetchCargoDeps
            cargo_workspace_flags=workspace-scoped
            RESULT
          '';
        }
      ];
    }
