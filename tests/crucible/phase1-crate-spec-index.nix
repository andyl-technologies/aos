{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;
  rfcDir = ../../docs/rfcs/0010-crucible;
  campaignRfcDir = ../../docs/rfcs/0020-crucible-campaigns;
  pagedRfcDir = ../../docs/rfcs/0021-crucible-paged-ram;

  specs = [
    {
      package = "crucible-cas";
      descriptiveContract = "Content-addressed objects, durable references, authenticated closures, and bounded storage operations";
      root = "src/lib.rs";
      specFiles = ["35"];
      section6 = true;
    }
    {
      package = "crucible-sim";
      descriptiveContract = "Deterministic randomness, counters, and virtual-time primitives";
      root = "src/lib.rs";
      specFiles = ["04" "08" "09"];
      section6 = true;
    }
    {
      package = "crucible-assert";
      descriptiveContract = "Deterministic assertion vocabulary and canonical subject identities";
      root = "src/lib.rs";
      specFiles = ["18"];
      section6 = true;
    }
    {
      package = "crucible-shmem";
      descriptiveContract = "Versioned shared-memory layouts, checked offsets, and process ownership";
      root = "src/lib.rs";
      specFiles = ["13"];
      section6 = true;
    }
    {
      package = "crucible-protocol";
      descriptiveContract = "Versioned control messages, bounded codecs, and descriptor exchange";
      root = "src/lib.rs";
      specFiles = ["14" "16"];
      section6 = true;
    }
    {
      package = "crucible-ram";
      descriptiveContract = "Paged RAM logical identity, persistent Merkle trees, and independent write epochs";
      root = "src/lib.rs";
      specFiles = [];
      pagedSpecFiles = ["02" "03"];
      section6 = false;
    }
    {
      package = "crucible-device";
      descriptiveContract = "Deterministic device queues and modeled I/O lifecycles";
      root = "src/lib.rs";
      specFiles = ["15"];
      section6 = true;
    }
    {
      package = "crucible-qemu";
      descriptiveContract = "Host-side QEMU process control, deterministic execution, and exact-state ownership";
      root = "src/lib.rs";
      specFiles = ["10" "11"];
      section6 = true;
    }
    {
      package = "crucible-qemu-plugin";
      descriptiveContract = "GPL-side guest observation, deterministic execution fences, and host paging";
      root = "src/lib.rs";
      specFiles = ["11" "12"];
      section6 = true;
    }
    {
      package = "crucible-debug-gateway";
      descriptiveContract = "Authenticated interactive debugging across the process boundary";
      root = "src/lib.rs";
      specFiles = ["36"];
      section6 = true;
    }
    {
      package = "crucible-guest";
      descriptiveContract = "Optional guest markers, typed selectable requests, and introspection helpers";
      root = "src/lib.rs";
      specFiles = ["16"];
      campaignSpecFiles = ["02"];
      section6 = true;
    }
    {
      package = "crucible";
      descriptiveContract = "Pure execution model, scheduling, faults, assertions, and replay identity";
      root = "src/lib.rs";
      specFiles = ["05" "06" "07" "08" "17" "18" "19"];
      section6 = true;
    }
    {
      package = "crucible-session";
      descriptiveContract = "Session control and lifecycle coordination at quantum boundaries";
      root = "src/lib.rs";
      specFiles = ["20"];
      section6 = true;
    }
    {
      package = "crucible-api";
      descriptiveContract = "Host lifecycle composition, exact checkpoints, and temporal graph APIs";
      root = "src/lib.rs";
      specFiles = ["21"];
      section6 = true;
    }
    {
      package = "crucible-daemon";
      descriptiveContract = "Campaign execution services, worker ownership, and host resource supervision";
      root = "src/lib.rs";
      specFiles = ["20" "21"];
      campaignSpecFiles = ["04a"];
      section6 = true;
    }
    {
      package = "crucible-cli";
      descriptiveContract = "Operator commands for execution, campaigns, debugging, and storage maintenance";
      root = "src/main.rs";
      specFiles = ["23"];
      section6 = true;
    }
    {
      package = "crucible-harness";
      descriptiveContract = "Executable conformance gates, independent replay checks, and ownership inventories";
      root = "src/lib.rs";
      specFiles = ["24" "27"];
      section6 = false;
    }
    {
      package = "crucible-campaign";
      descriptiveContract = "Campaign identity, typed graph storage, planning, and distributed executor contracts";
      root = "src/lib.rs";
      specFiles = [];
      campaignSpecFiles = ["01" "02" "04a" "06" "09"];
      section6 = false;
    }
    {
      package = "crucible-linux-resource";
      descriptiveContract = "Linux physical containment, host admission, and operational supervision";
      root = "src/lib.rs";
      specFiles = [];
      campaignSpecFiles = ["04a" "06"];
      section6 = false;
    }
    {
      package = "crucible-s3-store";
      descriptiveContract = "Authenticated remote object storage and durable reference coordination";
      root = "src/lib.rs";
      specFiles = [];
      campaignSpecFiles = ["06"];
      section6 = false;
    }
  ];

  expectedPackages = lib.sort builtins.lessThan (map (spec: spec.package) specs);
  foundPackages = lib.sort builtins.lessThan (
    builtins.filter (
      name:
        lib.hasPrefix "crucible" name
        && builtins.pathExists (cratesDir + "/${name}/Cargo.toml")
    ) (builtins.attrNames (builtins.readDir cratesDir))
  );

  packageSetFailures =
    if foundPackages == expectedPackages
    then []
    else [
      "crucible package set mismatch: expected [${builtins.concatStringsSep ", " expectedPackages}], found [${builtins.concatStringsSep ", " foundPackages}]"
    ];

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  linesOf = content: lib.splitString "\n" content;

  docPrefixLines = lines:
    if lines == []
    then []
    else let
      line = builtins.head lines;
      rest = builtins.tail lines;
    in
      if line == ""
      then docPrefixLines rest
      else if lib.hasPrefix "//!" line
      then [line] ++ docPrefixLines rest
      else [];

  campaignSpecFilesOf = spec: spec.campaignSpecFiles or [];
  expectedDocLine = spec: "//! Implementation contract: ${spec.descriptiveContract}.";

  crateDocFailures = spec: content: displayPath: let
    docLines = docPrefixLines (linesOf content);
    expected = expectedDocLine spec;
    indexLines = builtins.filter (line: lib.hasPrefix "//! Implementation contract:" line) docLines;
    obsoleteLines = builtins.filter (line: lib.hasPrefix "//! Spec index:" line) docLines;
  in
    if obsoleteLines != []
    then ["${displayPath}: obsolete numeric ownership header"]
    else if indexLines == [expected]
    then []
    else if indexLines == []
    then [
      "${displayPath}: missing exact implementation contract line `${expected}`"
    ]
    else [
      "${displayPath}: found Implementation contract lines [${builtins.concatStringsSep " | " indexLines}], expected exactly `${expected}`"
    ];

  rfcFileNames = builtins.attrNames (builtins.readDir rfcDir);
  rfcFileExists = file:
    builtins.any (name:
      lib.hasPrefix "${file}-" name && lib.hasSuffix ".md" name)
    rfcFileNames;
  campaignRfcFileNames = builtins.attrNames (builtins.readDir campaignRfcDir);
  campaignRfcFileExists = file:
    builtins.any (name:
      lib.hasPrefix "${file}-" name && lib.hasSuffix ".md" name)
    campaignRfcFileNames;

  pagedRfcFileNames = builtins.attrNames (builtins.readDir pagedRfcDir);
  pagedRfcFileExists = file:
    builtins.any (name:
      lib.hasPrefix "${file}-" name && lib.hasSuffix ".md" name)
    pagedRfcFileNames;

  realDocFailures =
    lib.concatMap (
      spec:
        crateDocFailures
        spec
        (builtins.readFile (cratesDir + "/${spec.package}/${spec.root}"))
        "crates/${spec.package}/${spec.root}"
    )
    specs;

  specFileFailures =
    lib.concatMap (
      spec:
        lib.concatMap (
          file:
            lib.optionals (!(rfcFileExists file)) [
              "${spec.package}: spec index references missing RFC-0010 file `${file}`"
            ]
        )
        spec.specFiles
        ++ lib.concatMap (
          file:
            lib.optionals (!(campaignRfcFileExists file)) [
              "${spec.package}: spec index references missing RFC-0020 file `${file}`"
            ]
        ) (campaignSpecFilesOf spec)
        ++ lib.concatMap (
          file:
            lib.optionals (!(pagedRfcFileExists file)) [
              "${spec.package}: spec index references missing paged RAM file `${file}`"
            ]
        ) (spec.pagedSpecFiles or [])
    )
    specs;

  section6Content = builtins.readFile (rfcDir + "/27-crate-structure.md");
  section6BlockLines = lines: inSection:
    if lines == []
    then []
    else let
      line = builtins.head lines;
      rest = builtins.tail lines;
    in
      if lib.hasPrefix "## 6. " line
      then section6BlockLines rest true
      else if inSection && lib.hasPrefix "## 7. " line
      then []
      else if inSection
      then [line] ++ section6BlockLines rest true
      else section6BlockLines rest false;
  section6Lines = section6BlockLines (linesOf section6Content) false;
  marker = file: "[`${file}`]";
  knownSpecFiles = ["04" "05" "06" "07" "08" "09" "10" "11" "12" "13" "14" "15" "16" "17" "18" "19" "20" "21" "23" "24" "27" "35"];

  rowForPackage = package:
    builtins.filter (line: lib.hasPrefix "| `${package}` |" line) section6Lines;

  packageInSection6Row = line: let
    matches = builtins.match "\\| `([^`]+)` \\|.*" line;
  in
    if matches == null
    then null
    else builtins.elemAt matches 0;

  expectedSectionPackages = map (spec: spec.package) (builtins.filter (spec: spec.section6) specs);
  actualSectionPackages =
    builtins.filter (package: package != null)
    (map packageInSection6Row section6Lines);
  unexpectedSectionPackages =
    builtins.filter (package: !(builtins.elem package expectedSectionPackages)) actualSectionPackages;

  section6RowFailures = spec: row: let
    missing =
      builtins.filter (file: !(hasInfix (marker file) row)) spec.specFiles;
    unexpected =
      builtins.filter (
        file:
          !(builtins.elem file spec.specFiles) && hasInfix (marker file) row
      )
      knownSpecFiles;
  in
    lib.optionals (missing != []) [
      "${spec.package}: section 6 row missing RFC file marker(s) [${builtins.concatStringsSep ", " missing}]"
    ]
    ++ lib.optionals (unexpected != []) [
      "${spec.package}: section 6 row contains unexpected RFC file marker(s) [${builtins.concatStringsSep ", " unexpected}], spec files must be [${builtins.concatStringsSep ", " spec.specFiles}]"
    ];

  section6Failures =
    lib.concatMap (
      spec:
        if !spec.section6
        then []
        else let
          rows = rowForPackage spec.package;
          rowCount = builtins.length rows;
        in
          if rowCount != 1
          then [
            "${spec.package}: expected exactly one section 6 crate/spec row, found ${builtins.toString rowCount}"
          ]
          else section6RowFailures spec (builtins.elemAt rows 0)
    )
    specs
    ++ map (package: "${package}: unexpected section 6 crate/spec row") unexpectedSectionPackages;

  regressionFailures = let
    spec = {
      package = "crucible-sim";
      descriptiveContract = "Deterministic randomness, counters, and virtual-time primitives";
      root = "src/lib.rs";
      specFiles = ["04" "08" "09"];
      section6 = true;
    };
    missingDocFindings = crateDocFailures spec ''
      //! synthetic crate doc
      #![forbid(unsafe_code)]
    '' "synthetic";
    wrongDocFindings = crateDocFailures spec ''
      //! synthetic crate doc
      //!
      //! Implementation contract: Deterministic randomness only.
      #![forbid(unsafe_code)]
    '' "synthetic";
    obsoleteDocFindings = crateDocFailures spec ''
      //! synthetic crate doc
      //! Spec index: RFC-0010 files 04, 08, 09.
      //! Implementation contract: Deterministic randomness, counters, and virtual-time primitives.
      #![forbid(unsafe_code)]
    '' "synthetic";
    staleRowFindings = section6RowFailures spec "| `crucible-sim` | [`04`](04-determinism-contract.md), [`09`](09-virtual-time-icount.md) | `gate:layer0-determinism` |";
    hasFinding = needle: findings:
      builtins.any (finding: hasInfix needle finding) findings;
  in
    lib.optionals (!(hasFinding "missing exact implementation contract" missingDocFindings)) [
      "spec-index regression failed to reject a missing crate-root doc line"
    ]
    ++ lib.optionals (!(hasFinding "found Implementation contract lines" wrongDocFindings)) [
      "spec-index regression failed to reject a wrong crate-root doc line"
    ]
    ++ lib.optionals (!(hasFinding "obsolete numeric ownership header" obsoleteDocFindings)) [
      "spec-index regression failed to reject an obsolete numeric ownership header"
    ]
    ++ lib.optionals (!(hasFinding "missing RFC file marker" staleRowFindings)) [
      "spec-index regression failed to reject a stale section 6 table row"
    ];

  failures = packageSetFailures ++ regressionFailures ++ realDocFailures ++ specFileFailures ++ section6Failures;
in
  if failures != []
  then throw "crucible phase1 crate spec-index lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-crate-spec-index";
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
            check=checks.crucible.phase1.crateSpecIndex
            tasks=T-CRATE-13
            crate_roots=15
            section6_rows=14
            RESULT
          '';
        }
      ];
    }
