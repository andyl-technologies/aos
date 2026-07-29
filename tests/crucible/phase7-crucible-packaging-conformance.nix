{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.cruciblePackagingConformance",
  taskIds ? ["T-PKG-16"],
  patchMicrotestsGate ? null,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  packagingSpec = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  defaultChecks = builtins.readFile ./default.nix;
  allSpecText = qemuPatchSpec + "\n" + packagingSpec;

  patchMicrotestsGateProvided = patchMicrotestsGate != null;

  patchFiles =
    builtins.sort builtins.lessThan
    (builtins.filter
      (name: lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patchDir)));
  manifestPatchFiles = series.patchFiles;
  manifestCatalogNames = map (patch: patch.catalogName) series.patches;
  catalogOnlyCapabilities = series.catalogOnlyCapabilities or [];
  catalogOnlyNames = map (capability: capability.catalogName) catalogOnlyCapabilities;
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

  section11_3 =
    builtins.elemAt
    (lib.splitString "## 11.4"
      (builtins.elemAt (lib.splitString "## 11.3 The patch catalog" qemuPatchSpec) 1))
    0;
  catalogRowLines =
    builtins.filter
    (line:
      lib.hasPrefix "  crucible-" line
      || lib.hasPrefix "  (crucible-" line)
    (lib.splitString "\n" section11_3);
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
      catalogOnlyCapabilities)
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

  qemuNixAppliesManifestSeries =
    hasInfix "patchCommand = file:" qemuNix
    && hasInfix "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)" qemuNix;
  qemuNixLines = lib.splitString "\n" qemuNix;
  trimLine = line: lib.trim line;
  qemuNixUnexpectedPatchCommandLines =
    builtins.filter
    (line: let
      trimmed = trimLine line;
      generatedManifestPatchCommand =
        hasInfix "patchCommand = file:" trimmed
        && hasInfix "patchPath file" trimmed;
    in
      hasInfix "patch -p1 <" trimmed
      && !(lib.hasPrefix "#" trimmed)
      && !generatedManifestPatchCommand)
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

  tokensFor = enforces:
    builtins.filter (token: token != "") (map lib.trim (lib.splitString "," enforces));
  isRequirementToken = token:
    builtins.match "([A-Z]+-[0-9]+|E[0-9]+)" token != null;
  isDocumentedCapabilityToken = token:
    builtins.elem token ["coverage" "PERF" "PLUG"];
  tokenIsStated = token:
    isRequirementToken token && (hasInfix "[${token}]" allSpecText || hasInfix token allSpecText)
    || isDocumentedCapabilityToken token && hasInfix token allSpecText;
  rowHasClass = row: class:
    hasInfix " ${class} " row;
  normalizeRowToken = token:
    lib.trim (builtins.replaceStrings ["," "(" ")" "." ";" ":"] ["" "" "" "" "" ""] token);
  rowTokensFor = row: class: let
    parts = lib.splitString " ${class} " row;
    tail =
      if builtins.length parts < 2
      then ""
      else builtins.elemAt parts 1;
  in
    builtins.filter
    (token: token != "")
    (map normalizeRowToken (lib.splitString " " tail));
  tokenSetDifference = left: right:
    builtins.filter (token: !(builtins.elem token right)) left;
  rowTokenFailuresFor = kind: name: row: class: enforces:
    if row == null
    then []
    else let
      manifestTokens = tokensFor enforces;
      rowTokens = rowTokensFor row class;
      missingManifestTokens = tokenSetDifference manifestTokens rowTokens;
      extraCatalogTokens = tokenSetDifference rowTokens manifestTokens;
    in
      map
      (token: "${kind} ${name}: section 11.3 catalog row is missing manifest enforces token ${token}")
      missingManifestTokens
      ++ map
      (token: "${kind} ${name}: section 11.3 catalog row has extra enforces token ${token}")
      extraCatalogTokens;
  rowClassFailuresFor = kind: name: row: class:
    if row == null || rowHasClass row class
    then []
    else [
      "${kind} ${name}: section 11.3 catalog row is missing manifest class ${class}"
    ];

  requirementFailuresFor = kind: name: enforces: let
    tokens = tokensFor enforces;
  in
    lib.optionals (tokens == []) [
      "${kind} ${name}: missing enforces mapping"
    ]
    ++ lib.optionals (!(builtins.any isRequirementToken tokens)) [
      "${kind} ${name}: enforces mapping must include at least one requirement id"
    ]
    ++ lib.concatMap
    (token:
      lib.optionals (!(tokenIsStated token)) [
        "${kind} ${name}: enforces token ${token} is not stated in RFC0010"
      ])
    tokens;

  patchRequirementFailures =
    lib.concatMap
    (patch: requirementFailuresFor "patch" patch.file patch.enforces)
    series.patches;
  patchCatalogRowFailures =
    lib.concatMap
    (patch: let
      row = catalogRowFor patch.catalogName;
    in
      rowClassFailuresFor "patch" patch.file row patch.class
      ++ rowTokenFailuresFor "patch" patch.file row patch.class patch.enforces)
    series.patches;
  catalogOnlyRequirementFailures =
    lib.concatMap
    (capability: requirementFailuresFor "catalog-only capability" capability.catalogName capability.enforces)
    catalogOnlyCapabilities;
  catalogOnlyRowFailures =
    lib.concatMap
    (capability: let
      row = catalogRowFor capability.catalogName;
    in
      rowClassFailuresFor "catalog-only capability" capability.catalogName row capability.class
      ++ rowTokenFailuresFor "catalog-only capability" capability.catalogName row capability.class capability.enforces)
    catalogOnlyCapabilities;

  catalogOnlyMappingFailures =
    lib.concatMap
    (capability:
      lib.optionals (!(builtins.elem capability.carriedBy manifestPatchFiles)) [
        "pkgs/emulation/qemu-patches/_series.nix: ${capability.catalogName} is carried by unknown patch ${capability.carriedBy}"
      ]
      ++ lib.optionals (!(hasInfix "`${capability.catalogName}` -> `${capability.carriedBy}`" qemuPatchSpec)) [
        "docs/rfcs/0010-crucible/11-qemu-patches.md: missing catalog-only carried-by mapping for ${capability.catalogName}"
      ])
    catalogOnlyCapabilities;


  failures =
    map (patch: "pkgs/emulation/qemu-patches/_series.nix: manifest references absent patch ${patch}")
    missingManifestPatches
    ++ map (patch: "pkgs/emulation/qemu-patches/${patch}: patch file is absent from the package manifest")
    unmanifestedPatchFiles
    ++ map (name: "docs/rfcs/0010-crucible/11-qemu-patches.md: section 11.3 catalog missing ${name}")
    missingCatalogRows
    ++ map (name: "docs/rfcs/0010-crucible/11-qemu-patches.md: section 11.3 catalog row ${name} is not mapped to shipped, catalog-only, dev-only, or not-carried inventory")
    unexpectedCatalogRows
    ++ lib.optionals (builtins.length catalogRowNames != builtins.length catalogRowLines) [
      "docs/rfcs/0010-crucible/11-qemu-patches.md: section 11.3 catalog has duplicate crucible-* row names"
    ]
    ++ lib.optionals (!qemuNixAppliesManifestSeries) [
      "pkgs/emulation/qemu.nix: shipped QEMU package must apply series.patchFiles from _series.nix"
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
    ++ map (name: "pkgs/emulation/qemu-patches/_series.nix: catalog-only capability must not be a shipped manifest patch: ${name}")
    catalogOnlyManifestCatalogNames
    ++ map (patch: "pkgs/emulation/qemu-patches/${patch}: dev-only diagnostic patch must not ship")
    devOnlyPatchFiles
    ++ map (name: "pkgs/emulation/qemu-patches/_series.nix: dev-only diagnostic patch must not be in shipped manifest: ${name}")
    devOnlyManifestCatalogNames
    ++ map (name: "pkgs/emulation/qemu.nix: shipped package references dev-only diagnostic patch ${name}")
    devOnlyQemuNixReferences
    ++ patchRequirementFailures
    ++ patchCatalogRowFailures
    ++ catalogOnlyRequirementFailures
    ++ catalogOnlyRowFailures
    ++ catalogOnlyMappingFailures
    ++ failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingSpec [
      {
        label = "T-PKG-16 checklist complete";
        needle = "- [x] **T-PKG-16**";
      }
      {
        label = "T-PKG-16 completion note";
        needle = "Completed by `checks.crucible.phase7.cruciblePackagingConformance`";
      }
      {
        label = "patch microtests gate reference";
        needle = "`checks.crucible.phase2.gates.patchMicrotests`";
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
            printf 'tasks=%s\n' "$TASK_IDS"
            printf '%s\n' 'gate=gate:patch-microtests'
            printf '%s\n' 'catalog=docs/rfcs/0010-crucible/11-qemu-patches.md#11.3'
            printf '%s\n' 'package_manifest=pkgs/emulation/qemu-patches/_series.nix'
            printf '%s\n' 'package=pkgs.qemu-crucible'
            printf 'manifest_patch_count=%s\n' "$MANIFEST_PATCH_COUNT"
            printf 'catalog_row_count=%s\n' "$CATALOG_ROW_COUNT"
            printf 'catalog_only_capability_count=%s\n' "$CATALOG_ONLY_COUNT"
            printf 'dev_only_catalog_count=%s\n' "$DEV_ONLY_COUNT"
            printf '%s\n' 'patch_directory_equals_manifest=true'
            printf '%s\n' 'manifest_equals_shipped_catalog_rows=true'
            printf '%s\n' 'manifest_class_and_enforces_match_catalog_rows=true'
            printf '%s\n' 'catalog_only_capabilities_mapped_to_carrier_patches=true'
            printf '%s\n' 'dev_only_patches_excluded=true'
            printf '%s\n' 'every_manifest_patch_maps_to_stated_requirement=true'
            printf '%s\n' 'qemu_package_applies_only_manifest_series=true'
            printf '%s\n' 'patch_microtests_gate=checks.crucible.phase2.gates.patchMicrotests'
            printf '%s\n' 'patch_microtests_gate_result_consumed=true'
          } > "$out/result"
        ''
      ];
      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      MANIFEST_PATCH_COUNT = toString (builtins.length manifestPatchFiles);
      CATALOG_ROW_COUNT = toString (builtins.length catalogRowNames);
      CATALOG_ONLY_COUNT = toString (builtins.length catalogOnlyCapabilities);
      DEV_ONLY_COUNT = toString (builtins.length devOnlyCatalogNames);
    }
