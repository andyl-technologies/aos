# Holds the QEMU atomic-patch license inventory to the artifact itself: every
# source file it creates must have a ledger row with a recognized license and
# a stated basis, and the ledger must not carry rows for files the artifact
# never creates. The check reads the patch rather than the bundle so drift fails at
# evaluation, before any QEMU build.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.qemuPatchLicenseLedger",
  taskIds ? ["T-CAM-6.8"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
  ledger = builtins.readFile (patchDir + "/LICENSES.md");

  recognizedLicenses = [
    "GPL-2.0-only"
    "GPL-2.0-or-later"
    "LGPL-2.1-or-later"
    "MIT"
    "MIT OR Apache-2.0"
    "BSD-3-Clause"
  ];

  # Walks the atomic patch's diff headers. A `new file mode` line announces that the
  # next `+++ b/` header names a created file; `deleted file mode` announces
  # that the next `--- a/` header names a removed one.
  atomicFileEvents = let
    lines = lib.splitString "\n" (builtins.readFile (patchDir + "/${atomicPatch.file}"));
    step = state: line:
      if lib.hasPrefix "new file mode" line
      then state // {pending = "created";}
      else if lib.hasPrefix "deleted file mode" line
      then state // {pending = "deleted";}
      else if state.pending == "created" && lib.hasPrefix "+++ b/" line
      then
        state
        // {
          pending = null;
          created = state.created ++ [(lib.removePrefix "+++ b/" line)];
        }
      else if state.pending == "deleted" && lib.hasPrefix "--- a/" line
      then
        state
        // {
          pending = null;
          deleted = state.deleted ++ [(lib.removePrefix "--- a/" line)];
        }
      else if lib.hasPrefix "diff --git " line
      then state // {pending = null;}
      else state;
    result =
      builtins.foldl' step {
        pending = null;
        created = [];
        deleted = [];
      }
      lines;
  in {
    inherit (result) created deleted;
  };

  createdFiles = lib.unique atomicFileEvents.created;
  deletedFiles = lib.unique atomicFileEvents.deleted;

  # Ledger rows look like ``| `path` | license | basis |``; the header and
  # separator rows carry no backticked path and are skipped.
  ledgerRows = lib.concatMap (
    line: let
      cells = map lib.trim (lib.splitString "|" line);
      # A row splits into ["" path license basis ""].
      isRow = builtins.length cells == 5 && lib.hasPrefix "`" (builtins.elemAt cells 1);
      path = lib.removeSuffix "`" (lib.removePrefix "`" (builtins.elemAt cells 1));
    in
      lib.optionals isRow [
        {
          inherit path;
          license = builtins.elemAt cells 2;
          basis = builtins.elemAt cells 3;
        }
      ]
  ) (lib.splitString "\n" ledger);
  ledgerPaths = map (row: row.path) ledgerRows;

  missingRowFailures =
    lib.concatMap (
      file:
        lib.optionals (!(builtins.elem file ledgerPaths)) [
          "LICENSES.md lacks a row for created file `${file}`"
        ]
    )
    createdFiles;

  staleRowFailures =
    lib.concatMap (
      row:
        if builtins.elem row.path deletedFiles
        then ["LICENSES.md keeps a row for `${row.path}`, which the atomic patch deletes"]
        else if !(builtins.elem row.path createdFiles)
        then ["LICENSES.md lists `${row.path}`, which the atomic patch does not create"]
        else []
    )
    ledgerRows;

  rowContentFailures =
    lib.concatMap (
      row:
        (lib.optionals (!(builtins.elem row.license recognizedLicenses)) [
          "LICENSES.md row `${row.path}` carries unrecognized license `${row.license}`"
        ])
        ++ (lib.optionals (row.basis == "") [
          "LICENSES.md row `${row.path}` states no basis"
        ])
    )
    ledgerRows;

  duplicateRowFailures = lib.optionals (lib.unique ledgerPaths != ledgerPaths) [
    "LICENSES.md lists a file more than once"
  ];

  # The scanner must see the created files the atomic artifact is known to add; an
  # empty scan would pass every ledger row vacuously.
  scannerFailures = lib.optionals (createdFiles == []) [
    "atomic patch scanner found no created files"
  ];

  failures = scannerFailures ++ missingRowFailures ++ staleRowFailures ++ rowContentFailures ++ duplicateRowFailures;
in
  if failures != []
  then throw "crucible phase6 qemu patch license ledger check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-qemu-patch-license-ledger";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            gate=gate:license-boundary
            tasks=${builtins.concatStringsSep "," taskIds}
            atomic_patch=${atomicPatch.file}
            created_files=${builtins.toString (builtins.length createdFiles)}
            deleted_files=${builtins.toString (builtins.length deletedFiles)}
            ledger_rows=${builtins.toString (builtins.length ledgerRows)}
            RESULT
          '';
        }
      ];
    }
