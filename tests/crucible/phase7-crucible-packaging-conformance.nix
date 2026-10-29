{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.cruciblePackagingConformance",
  patchMicrotestsGate ? null,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  qemuPatchDoc = builtins.readFile ../../docs/engineering/crucible/qemu-patch.md;
  testingAndGatesDoc = builtins.readFile ../../docs/engineering/crucible/testing-and-gates.md;
  defaultChecks = builtins.readFile ./default.nix;

  patchMicrotestsGateProvided = patchMicrotestsGate != null;

  patchFiles =
    builtins.sort builtins.lessThan
    (builtins.filter
      (name: lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patchDir)));
  manifestPatchFiles = [atomicPatch.file];
  manifestCatalogNames = map (patch: patch.catalogName) [atomicPatch];
  additionalCapabilities = atomicPatch.additionalCapabilities or [];
  catalogOnlyNames = map (capability: capability.catalogName) additionalCapabilities;
  devOnlyCatalogNames = [
    "crucible-tcg-exec-diag"
    "crucible-virtserial-socket"
  ];
  notCarriedCatalogNames = [
    "crucible-replay-start"
  ];
  expectedCatalogNames =
    manifestCatalogNames
    ++ catalogOnlyNames
    ++ devOnlyCatalogNames
    ++ notCarriedCatalogNames;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  # The "## Catalog" section of the patch page, up to the next level-two heading.
  catalogSectionParts = lib.splitString "\n## Catalog\n" qemuPatchDoc;
  catalogSection =
    if builtins.length catalogSectionParts < 2
    then ""
    else builtins.elemAt (lib.splitString "\n## " (builtins.elemAt catalogSectionParts 1)) 0;
  catalogRowLines =
    builtins.filter
    (line:
      lib.hasPrefix "  crucible-" line
      || lib.hasPrefix "  rr-" line
      || lib.hasPrefix "  (crucible-" line)
    (lib.splitString "\n" catalogSection);
  firstField = value: let
    fields = builtins.filter (field: field != "") (lib.splitString " " (lib.trim value));
  in
    builtins.elemAt fields 0;
  catalogNameFromRow = row:
    lib.removeSuffix ")" (lib.removePrefix "(" (firstField row));
  catalogRowNames = lib.unique (map catalogNameFromRow catalogRowLines);
  catalogRowsFor = name:
    builtins.filter (row: catalogNameFromRow row == name) catalogRowLines;
  catalogRowFor = name: let
    matches = catalogRowsFor name;
  in
    if matches == []
    then null
    else builtins.elemAt matches 0;

  missingCatalogRows =
    builtins.filter (name: !(builtins.elem name catalogRowNames)) expectedCatalogNames;
  unexpectedCatalogRows =
    builtins.filter (name: !(builtins.elem name expectedCatalogNames)) catalogRowNames;
  missingManifestPatches =
    builtins.filter (patch: !(builtins.elem patch patchFiles)) manifestPatchFiles;
  unmanifestedPatchFiles =
    builtins.filter (patch: !(builtins.elem patch manifestPatchFiles)) patchFiles;
  catalogOnlyPatchFiles =
    builtins.filter
    (patch:
      builtins.any
      (capability: hasInfix capability.catalogName patch)
      additionalCapabilities)
    patchFiles;
  catalogOnlyManifestCatalogNames =
    builtins.filter (name: builtins.elem name catalogOnlyNames) manifestCatalogNames;
  devOnlyPatchFiles =
    builtins.filter
    (patch:
      builtins.any
      (catalogName: hasInfix catalogName patch)
      devOnlyCatalogNames)
    patchFiles;
  devOnlyManifestCatalogNames =
    builtins.filter (name: builtins.elem name devOnlyCatalogNames) manifestCatalogNames;
  devOnlyQemuNixReferences =
    builtins.filter (name: hasInfix name qemuNix) devOnlyCatalogNames;

  qemuNixAppliesAtomicPatch =
    hasInfix "atomicPatchPath = patchDir + \"/\${atomicPatch.file}\";" qemuNix
    && hasInfix "< \${atomicPatchPath}" qemuNix;
  qemuNixLines = lib.splitString "\n" qemuNix;
  trimLine = line: lib.trim line;
  qemuNixUnexpectedPatchCommandLines =
    builtins.filter
    (line: let
      trimmed = trimLine line;
      atomicPatchCommand = hasInfix "< \${atomicPatchPath}" trimmed;
    in
      hasInfix "patch -p1 <" trimmed
      && !(lib.hasPrefix "#" trimmed)
      && !atomicPatchCommand)
    qemuNixLines;
  patchRefFromLine = line: let
    match = builtins.match ".*qemu-patches/([^} \"]+\\.patch).*" line;
  in
    if match == null
    then null
    else builtins.elemAt match 0;
  qemuNixExplicitPatchRefs =
    builtins.filter (patch: patch != null) (map patchRefFromLine qemuNixLines);
  qemuNixUnexpectedPatchRefs =
    builtins.filter (patch: !(builtins.elem patch manifestPatchFiles)) qemuNixExplicitPatchRefs;

  # A catalog row is `  <name> ....... <class>`; the class is the last field.
  rowHasClass = row: class:
    lib.hasSuffix " ${class}" (lib.trim row);
  rowClassFailuresFor = kind: name: row: class:
    if row == null || rowHasClass row class
    then []
    else [
      "${kind} ${name}: docs/engineering/crucible/qemu-patch.md catalog row is missing manifest class ${class}"
    ];

  patchCatalogRowFailures =
    lib.concatMap
    (patch: rowClassFailuresFor "patch" patch.file (catalogRowFor patch.catalogName) patch.class)
    [atomicPatch];
  catalogOnlyRowFailures =
    lib.concatMap
    (capability:
      rowClassFailuresFor
      "catalog-only capability"
      capability.catalogName
      (catalogRowFor capability.catalogName)
      capability.class)
    additionalCapabilities;

  catalogOnlyMappingFailures =
    lib.concatMap
    (capability:
      lib.optionals (!(builtins.elem capability.carriedBy manifestPatchFiles)) [
        "pkgs/emulation/qemu-patches/_atomic-patch.nix: ${capability.catalogName} is carried by unknown patch ${capability.carriedBy}"
      ]
      ++ lib.optionals (!(hasInfix "`${capability.catalogName}` -> `${capability.carriedBy}`" qemuPatchDoc)) [
        "docs/engineering/crucible/qemu-patch.md: missing catalog-only carried-by mapping for ${capability.catalogName}"
      ])
    additionalCapabilities;

  failures =
    map (patch: "pkgs/emulation/qemu-patches/_atomic-patch.nix: manifest references absent patch ${patch}")
    missingManifestPatches
    ++ map (patch: "pkgs/emulation/qemu-patches/${patch}: patch file is absent from the package manifest")
    unmanifestedPatchFiles
    ++ lib.optionals (catalogSection == "") [
      "docs/engineering/crucible/qemu-patch.md: missing \"## Catalog\" section"
    ]
    ++ map (name: "docs/engineering/crucible/qemu-patch.md: catalog missing ${name}")
    missingCatalogRows
    ++ map (name: "docs/engineering/crucible/qemu-patch.md: catalog row ${name} is not mapped to shipped, catalog-only, dev-only, or not-carried inventory")
    unexpectedCatalogRows
    ++ lib.optionals (builtins.length catalogRowNames != builtins.length catalogRowLines) [
      "docs/engineering/crucible/qemu-patch.md: catalog has duplicate crucible-* row names"
    ]
    ++ lib.optionals (!qemuNixAppliesAtomicPatch) [
      "pkgs/emulation/qemu.nix: shipped QEMU package must directly apply the atomic patch"
    ]
    ++ map (line: "pkgs/emulation/qemu.nix: unexpected non-manifest patch command line: ${trimLine line}")
    qemuNixUnexpectedPatchCommandLines
    ++ map (patch: "pkgs/emulation/qemu.nix: unexpected qemu-patches patch reference outside manifest: ${patch}")
    qemuNixUnexpectedPatchRefs
    ++ lib.optionals (!patchMicrotestsGateProvided) [
      "tests/crucible/default.nix: phase7 packaging conformance requires the direct phase2 patch-microtests aggregate"
    ]
    ++ map (patch: "pkgs/emulation/qemu-patches/${patch}: catalog-only capability must not exist as an extra shipped patch file")
    catalogOnlyPatchFiles
    ++ map (name: "pkgs/emulation/qemu-patches/_atomic-patch.nix: catalog-only capability must not be a shipped manifest patch: ${name}")
    catalogOnlyManifestCatalogNames
    ++ map (patch: "pkgs/emulation/qemu-patches/${patch}: dev-only diagnostic patch must not ship")
    devOnlyPatchFiles
    ++ map (name: "pkgs/emulation/qemu-patches/_atomic-patch.nix: dev-only diagnostic patch must not be in shipped manifest: ${name}")
    devOnlyManifestCatalogNames
    ++ map (name: "pkgs/emulation/qemu.nix: shipped package references dev-only diagnostic patch ${name}")
    devOnlyQemuNixReferences
    ++ patchCatalogRowFailures
    ++ catalogOnlyRowFailures
    ++ catalogOnlyMappingFailures
    ++ failuresFor "docs/engineering/crucible/testing-and-gates.md" testingAndGatesDoc [
      {
        label = "patch microtests gate reference";
        needle = "checks.crucible.phase2.gates.patchMicrotests";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 packaging conformance check imported";
        needle = "cruciblePackagingConformance = import ./phase7-crucible-packaging-conformance.nix";
      }
      {
        label = "phase7 packaging conformance receives direct patch microtests check";
        needle = "patchMicrotestsGate = import ./phase2-patch-microtests.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 packaging conformance check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    builtins.derivation {
      name = "crucible-phase7-packaging-conformance-0";
      inherit (lib) system;
      builder = "${pkgs.bash}/bin/bash";
      PATH = "${pkgs.coreutils}/bin:${pkgs.grep}/bin";
      PATCH_MICROTESTS_GATE = patchMicrotestsGate;
      args = [
        "-c"
        ''
          set -eu
          mkdir -p "$out"

          grep -q '^PASS$' "$PATCH_MICROTESTS_GATE/result"

          {
            printf '%s\n' 'PASS'
            printf 'check=%s\n' "$ATTR_PATH"
            printf '%s\n' 'gate=gate:patch-microtests'
            printf '%s\n' 'catalog=docs/engineering/crucible/qemu-patch.md#catalog'
            printf '%s\n' 'package_manifest=pkgs/emulation/qemu-patches/_atomic-patch.nix'
            printf '%s\n' 'package=pkgs.qemu-crucible'
            printf 'atomic_patch=%s\n' "$ATOMIC_PATCH"
            printf 'catalog_row_count=%s\n' "$CATALOG_ROW_COUNT"
            printf 'catalog_only_capability_count=%s\n' "$CATALOG_ONLY_COUNT"
            printf 'dev_only_catalog_count=%s\n' "$DEV_ONLY_COUNT"
            printf '%s\n' 'patch_directory_equals_manifest=true'
            printf '%s\n' 'manifest_equals_shipped_catalog_rows=true'
            printf '%s\n' 'manifest_class_matches_catalog_rows=true'
            printf '%s\n' 'catalog_only_capabilities_mapped_to_carrier_patches=true'
            printf '%s\n' 'dev_only_patches_excluded=true'
            printf '%s\n' 'qemu_package_applies_atomic_patch=true'
            printf '%s\n' 'patch_microtests_gate=checks.crucible.phase2.gates.patchMicrotests'
            printf '%s\n' 'patch_microtests_gate_result_consumed=true'
          } > "$out/result"
        ''
      ];
      ATTR_PATH = attrPath;
      ATOMIC_PATCH = atomicPatch.file;
      CATALOG_ROW_COUNT = toString (builtins.length catalogRowNames);
      CATALOG_ONLY_COUNT = toString (builtins.length additionalCapabilities);
      DEV_ONLY_COUNT = toString (builtins.length devOnlyCatalogNames);
    }
