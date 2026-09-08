{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleWorkspacePackage",
  taskIds ? ["T-PKG-8"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};

  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  cruciblePackageNix = builtins.readFile ../../pkgs/tools/crucible/crucible.nix;
  packageSetNix = builtins.readFile ../../pkgs/default.nix;
  phaseTemplatesNix = builtins.readFile ../../stdenv/phases.nix;
  phaseTemplates = import ../../stdenv/phases.nix;
  cargoDepsHash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  expectedCargoDepsHash = "sha256-RvgGglI1TqzOmlqgt3qG+GBHEGd3ZHT9M4CueO0Q/W4=";
  packageInventory = import ../../pkgs/tools/crucible/_packages.nix;
  workspaceManifest = builtins.fromTOML (builtins.readFile ../../crates/Cargo.toml);
  defaultChecks = builtins.readFile ./default.nix;

  workspaceMembers = workspaceManifest.workspace.members;
  crucibleWorkspaceMembers = builtins.filter (member: lib.hasPrefix "crucible" member) workspaceMembers;
  missingInventoryMembers =
    builtins.filter (member: !(builtins.elem member packageInventory)) crucibleWorkspaceMembers;
  extraInventoryMembers =
    builtins.filter (member: !(builtins.elem member workspaceMembers)) packageInventory;

  nextestCheckScript = limit: let
    phases = phaseTemplates.cargoPhases {
      cargoDeps = "/build/cargo-vendor";
      cargoNextest = "/build/cargo-nextest";
      cargoNextestOpenFilesLimit = limit;
      doCheck = true;
    };
    checkPhase = lib.findFirst (phase: phase.name == "check") null phases;
  in
    if checkPhase == null
    then throw "stdenv cargo phases did not produce a check phase"
    else checkPhase.script;
  nullNextestCheckScript = nextestCheckScript null;
  boundedNextestCheckScript = nextestCheckScript 4096;
  invalidNextestLimit = builtins.tryEval (builtins.deepSeq (nextestCheckScript 0) true);

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
        needle = "cargoDeps = fetchCargoVendor";
      }
      {
        label = "central vendored dependency hash binding";
        needle = "cargoDepsHash = import ./_cargo-deps-hash.nix;";
      }
      {
        label = "vendored dependency hash consumed by cargo deps";
        needle = "hash = cargoDepsHash;";
      }
      {
        label = "non-Crucible workspace excludes";
        needle = "nonCrucibleWorkspacePackages = builtins.filter";
      }
      {
        label = "workspace membership comes from Cargo metadata";
        needle = "workspacePackages = (builtins.fromTOML (builtins.readFile ../../../crates/Cargo.toml)).workspace.members;";
      }
      {
        label = "workspace cargo flags";
        needle = "workspaceCargoFlags = builtins.concatStringsSep \" \"";
      }
      {
        label = "workspace cargo build";
        needle = "cargoFlags = packageFlags;";
      }
      {
        label = "workspace cargo test";
        needle = "cargoTestFlags = \"" + "$" + "{packageFlags} --features crucible-cli/test-double\";";
      }
      {
        label = "package checks enabled";
        needle = "doCheck = true;";
      }
      {
        label = "bounded controller Nextest open-file ceiling";
        needle = "cargoNextestOpenFilesLimit = 4096;";
      }
      {
        label = "bounded Nextest ceiling recorded in build metadata";
        needle = "cargo_nextest_open_files_limit=4096";
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
        needle = "cargo test \\\n            --doc";
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
        needle = "license = [\"Apache-2.0\" \"MIT\" \"GPL-2.0-only\" \"GPL-2.0-or-later\" \"GPL-3.0-or-later\" \"BSD-2-Clause\" \"BSD-3-Clause\"];";
      }
      {
        label = "workspace build info";
        needle = "cargo_workspace_flags=" + "$" + "{workspaceCargoFlags}";
      }
    ]
    ++ failuresFor "pkgs/default.nix" packageSetNix [
      {
        label = "Nextest open-file limit consumed by Cargo wrapper";
        needle = ''"cargoNextestOpenFilesLimit"'';
      }
    ]
    ++ failuresFor "stdenv/phases.nix" phaseTemplatesNix [
      {
        label = "Nextest open-file limit validates positive integers";
        needle = ''else throw "cargoNextestOpenFilesLimit must be a positive integer";'';
      }
      {
        label = "Nextest installs the bounded soft descriptor limit";
        needle = "ulimit -S -n " + "$" + "{toString validatedNextestOpenFilesLimit}";
      }
      {
        label = "Nextest verifies the installed descriptor limit";
        needle = ''nextestOpenFilesLimit=$(ulimit -S -n)'';
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
    ++ lib.optional (cargoDepsHash != expectedCargoDepsHash) "pkgs/tools/crucible/_cargo-deps-hash.nix: expected pinned vendored dependency hash `${expectedCargoDepsHash}`, got `${cargoDepsHash}`"
    ++ lib.optional invalidNextestLimit.success "stdenv/phases.nix: zero Nextest open-file limit must fail evaluation"
    ++ lib.optional (hasInfix "ulimit -S -n" nullNextestCheckScript) "stdenv/phases.nix: null Nextest open-file limit unexpectedly changes the shell limit"
    ++ lib.optional (!hasInfix "ulimit -S -n 4096" boundedNextestCheckScript) "stdenv/phases.nix: generated 4096-limit check phase does not install the requested bound"
    ++ lib.optional (!hasInfix ''nextestOpenFilesLimit=$(ulimit -S -n)'' boundedNextestCheckScript) "stdenv/phases.nix: generated 4096-limit check phase does not verify the installed limit"
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
            cargo_deps=fetchCargoVendor
            cargo_workspace_flags=workspace-scoped
            nextest_open_file_limit_policy=validated-null-or-positive-integer
            nextest_open_file_limit_generated_phase=4096
            RESULT
          '';
        }
      ];
    }
