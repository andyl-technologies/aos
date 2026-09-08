# Holds the QEMU patch-series license inventory to the series itself: every
# source file a patch creates must have a ledger row with a recognized license
# and a stated basis, a file a later patch deletes must not keep a row, and the
# ledger must not carry rows for files the series never creates. The check
# reads the patch files rather than the bundle so a ledger drift fails at
# evaluation, before any QEMU build.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.qemuPatchLicenseLedger",
  taskIds ? ["T-CAM-6.8"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import (patchDir + "/_series.nix");
  ledger = builtins.readFile (patchDir + "/LICENSES.md");

  recognizedLicenses = ["GPL-2.0-only" "GPL-2.0-or-later" "MIT OR Apache-2.0"];

  # Walks one patch's diff headers. A `new file mode` line announces that the
  # next `+++ b/` header names a created file; `deleted file mode` announces
  # that the next `--- a/` header names a removed one.
  fileEventsOf = patch: let
    lines = lib.splitString "\n" (builtins.readFile (patchDir + "/${patch.file}"));
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
    patch = patch.file;
  };

  events = map fileEventsOf series.patches;

  # A file created by one patch and deleted by a later one leaves the tree
  # and must leave the ledger with it.
  createdFiles = lib.unique (lib.concatMap (event: event.created) events);
  deletedFiles = lib.unique (lib.concatMap (event: event.deleted) events);
  presentFiles = builtins.filter (file: !(builtins.elem file deletedFiles)) createdFiles;

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
    presentFiles;

  staleRowFailures =
    lib.concatMap (
      row:
        if builtins.elem row.path deletedFiles
        then ["LICENSES.md keeps a row for `${row.path}`, which the series deletes"]
        else if !(builtins.elem row.path createdFiles)
        then ["LICENSES.md lists `${row.path}`, which no patch creates"]
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

  # The scanner must see the created files the series is known to add; an
  # empty scan would pass every ledger row vacuously.
  scannerFailures = lib.optionals (createdFiles == []) [
    "patch scanner found no created files across ${builtins.toString (builtins.length series.patches)} patches"
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
            patches=${builtins.toString (builtins.length series.patches)}
            created_files=${builtins.toString (builtins.length createdFiles)}
            deleted_files=${builtins.toString (builtins.length deletedFiles)}
            ledger_rows=${builtins.toString (builtins.length ledgerRows)}
            RESULT
          '';
        }
      ];
    }
