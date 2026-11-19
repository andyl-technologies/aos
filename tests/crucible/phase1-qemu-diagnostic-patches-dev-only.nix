{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.qemuDiagnosticPatchesDevOnly",
  taskIds ? ["T-PATCH-18"],
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  qemuPatchDoc = builtins.readFile ../../docs/engineering/crucible/qemu-patch.md;
  packagingDoc = builtins.readFile ../../docs/engineering/crucible/packaging.md;
  defaultChecks = builtins.readFile ./default.nix;
  patchFiles =
    builtins.sort builtins.lessThan
    (builtins.filter
      (name: lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patchDir)));
  diagnosticPatchNames = [
    "crucible-tcg-exec-diag"
    "crucible-virtserial-socket"
  ];
  qemuPackageResultLines =
    if qemuPackage == null
    then ''
      qemu_package=standalone-fixture
      qemu_package_version=standalone-fixture
    ''
    else ''
      qemu_package=${qemuPackage}
      qemu_package_version=${qemuPackage.version}
    '';

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  shippedDiagnosticPatchFiles =
    builtins.filter
    (patch:
      builtins.any
      (diagnosticName: hasInfix diagnosticName patch)
      diagnosticPatchNames)
    patchFiles;
  qemuNixDiagnosticNeedles =
    builtins.filter (diagnosticName: hasInfix diagnosticName qemuNix) diagnosticPatchNames;

  failures =
    map (patch: "pkgs/emulation/qemu-patches/${patch}: diagnostic-only patch must not ship in qemu-crucible")
    shippedDiagnosticPatchFiles
    ++ map (diagnosticName: "pkgs/emulation/qemu.nix: shipped qemu-crucible package applies diagnostic-only patch ${diagnosticName}")
    qemuNixDiagnosticNeedles
    ++ lib.optionals (!(hasInfix "are not applied by the shipped package" qemuPatchDoc && hasInfix "`checks.crucible.phase1.qemuDiagnosticPatchesDevOnly`" qemuPatchDoc)) [
      "docs/engineering/crucible/qemu-patch.md: shipped diagnostic exclusion requirement missing"
    ]
    ++ lib.optionals (!(hasInfix "diagnostic QEMU patch ships" packagingDoc && hasInfix "diagnostic-only capabilities are absent" packagingDoc)) [
      "docs/engineering/crucible/packaging.md: shipped diagnostic exclusion requirement missing"
    ]
    ++ lib.optionals (!(hasInfix "qemuDiagnosticPatchesDevOnly = import ./phase1-qemu-diagnostic-patches-dev-only.nix" defaultChecks)) [
      "tests/crucible/default.nix: phase1 diagnostic patch exclusion check is not exposed"
    ];
in
  if failures != []
  then throw "crucible phase1 QEMU diagnostic patch exclusion check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-qemu-diagnostic-patches-dev-only";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
      ];

      phases = [
        {
          name = "check-qemu-diagnostic-patches-dev-only";
          script = ''
            set -eu

            mkdir -p "$out"
            test -x ${qemuPackage}/bin/qemu-system-x86_64
            test -f ${qemuPackage}/include/qemu-plugin.h

            if find ${patchDir} -type f \( -name '*crucible-tcg-exec-diag*' \
              -o -name '*crucible-virtserial-socket*' \) | grep -q .; then
              echo "diagnostic-only QEMU patch is present in shipped patch directory" >&2
              exit 1
            fi

            if grep -F -q 'crucible-tcg-exec-diag' ${../../pkgs/emulation/qemu.nix} ||
               grep -F -q 'crucible-virtserial-socket' ${../../pkgs/emulation/qemu.nix}; then
              echo "diagnostic-only QEMU patch is applied by shipped qemu-crucible" >&2
              exit 1
            fi

            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            gate=gate:qemu-inert
            gate=gate:patch-microtests
            patch=no-shipped-diagnostic-patch
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            qemu_diagnostic_patches_shipped=false
            diagnostic_patch_count=0
            crucible_tcg_exec_diag_shipped=false
            crucible_virtserial_socket_shipped=false
            qemu_crucible_dev_variant_present=false
            dev_only_diagnostic_patches_inert_by_default=true
            RESULT
          '';
        }
      ];
    }
