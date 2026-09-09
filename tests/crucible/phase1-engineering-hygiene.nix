{
  pkgs,
  lib,
}: let
  root = ../..;
  cratesDir = ../../crates;
  defaultNix = builtins.readFile ./default.nix;
  hygieneRust = builtins.readFile ../../crates/crucible-harness/tests/engineering_hygiene.rs;
  hygieneBaselineText = builtins.readFile ./engineering-hygiene-baseline.txt;

  responsibilityReviewThreshold = 1000;
  cohesionReviewThreshold = 1500;
  legacyShapeLineStaleThreshold = 600;
  cohesionNotRequired = "threshold-not-reached";

  cruciblePackages = [
    "crucible-sim"
    "crucible-assert"
    "crucible-shmem"
    "crucible-protocol"
    "crucible-device"
    "crucible-qemu"
    "crucible-qemu-plugin"
    "crucible-guest"
    "crucible-cas"
    "crucible-campaign"
    "crucible"
    "crucible-session"
    "crucible-api"
    "crucible-daemon"
    "crucible-cli"
    "crucible-harness"
  ];
  qemuBoundaryPackages = ["crucible-debug-gateway" "crucible-daemon" "crucible-qemu" "crucible-qemu-plugin"];
  qemuSpecificTokens = [
    "qemu"
    "Qemu"
    "QEMU"
    "qmp"
    "Qmp"
    "QMP"
    "savevm"
    "loadvm"
    "crucible_qemu"
  ];

  commitHygieneRules = [
    {
      id = "atomic-logical-change";
      terms = ["focused and atomic" "logical change"];
    }
    {
      id = "imperative-summary";
      terms = ["imperative summary"];
    }
    {
      id = "abi-golden-engine-together";
      terms = ["versioned ABI" "golden-vector" "engine logic"];
    }
    {
      id = "no-determinism-format-churn";
      terms = ["determinism-relevant change" "unrelated formatting churn"];
    }
  ];

  hygieneBaselineLines =
    builtins.filter (line: line != "" && !(lib.hasPrefix "#" line))
    (lib.splitString "\n" hygieneBaselineText);
  parseBaselineLine = line: let
    fields = lib.splitString "|" line;
    fieldCount = builtins.length fields;
    kind = builtins.elemAt fields 0;
  in
    if kind == "shape-line" && fieldCount == 3
    then {
      kind = "shape-line";
      path = builtins.elemAt fields 1;
      maxLines = builtins.fromJSON (builtins.elemAt fields 2);
    }
    else if kind == "shape-review" && fieldCount == 7
    then {
      kind = "shape-review";
      path = builtins.elemAt fields 1;
      digest = builtins.elemAt fields 2;
      role = builtins.elemAt fields 3;
      lines = builtins.fromJSON (builtins.elemAt fields 4);
      responsibilities = builtins.elemAt fields 5;
      cohesion = builtins.elemAt fields 6;
    }
    else if kind == "shape-header" && fieldCount == 2
    then {
      kind = "shape-header";
      path = builtins.elemAt fields 1;
    }
    else if kind == "qemu-token" && fieldCount == 4
    then {
      kind = "qemu-token";
      package = builtins.elemAt fields 1;
      path = builtins.elemAt fields 2;
      token = builtins.elemAt fields 3;
    }
    else if kind == "qemu-manifest" && fieldCount == 5
    then {
      kind = "qemu-manifest";
      package = builtins.elemAt fields 1;
      path = builtins.elemAt fields 2;
      dependency = builtins.elemAt fields 3;
      scope = builtins.elemAt fields 4;
    }
    else throw "invalid engineering hygiene baseline entry: ${line}";
  hygieneBaseline = map parseBaselineLine hygieneBaselineLines;
  shapeLineDebt = builtins.filter (entry: entry.kind == "shape-line") hygieneBaseline;
  sourceReviews = builtins.filter (entry: entry.kind == "shape-review") hygieneBaseline;
  shapeHeaderDebt = builtins.filter (entry: entry.kind == "shape-header") hygieneBaseline;
  qemuTokenDebt = builtins.filter (entry: entry.kind == "qemu-token") hygieneBaseline;
  qemuManifestDebt = builtins.filter (entry: entry.kind == "qemu-manifest") hygieneBaseline;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  # Character-exact scrub of Rust comments and string literals. The fold is
  # chunked per source line (each chunk keeps its trailing newline, and the
  # parser state — mode/depth/skip — threads across chunks) with the output
  # string forced after every chunk. A whole-file per-character fold builds a
  # haystack-deep chain of unforced `+` thunks and overflows the evaluator
  # stack on large sources.
  scrubCommentsAndStrings = content: let
    scrubChunk = chunkState: chunk: let
      length = builtins.stringLength chunk;
      charAt = index:
        if index < length
        then builtins.substring index 1 chunk
        else "";
      spaces = count: builtins.concatStringsSep "" (builtins.genList (_: " ") count);
      countHashes = index:
        if charAt index == "#"
        then 1 + countHashes (index + 1)
        else 0;
      rawStartAt = index: let
        prefixLength =
          if charAt index == "r"
          then 1
          else if charAt index == "b" && charAt (index + 1) == "r"
          then 2
          else 0;
        hashStart = index + prefixLength;
        hashes = countHashes hashStart;
        openerLength = prefixLength + hashes + 1;
      in
        if prefixLength > 0 && charAt (hashStart + hashes) == "\""
        then {inherit hashes openerLength;}
        else null;
      rawClosesAt = hashes: index:
        charAt index
        == "\""
        && builtins.all
        (offset: charAt (index + 1 + offset) == "#")
        (builtins.genList (offset: offset) hashes);
      charLiteralLengthAt = index:
        if charAt index != "'"
        then 0
        else if charAt (index + 1) == "\\" && charAt (index + 3) == "'"
        then 4
        else if charAt (index + 2) == "'"
        then 3
        else 0;
      indexes = builtins.genList (index: index) length;
      folded = builtins.foldl' step chunkState indexes;
      step = state: index:
        if state.skip > 0
        then
          state
          // {
            skip = state.skip - 1;
          }
        else let
          ch = charAt index;
          next = charAt (index + 1);
          rawStart = rawStartAt index;
          charLiteralLength = charLiteralLengthAt index;
        in
          if state.mode == "code"
          then
            if ch == "/" && next == "/"
            then
              state
              // {
                out = state.out + "  ";
                mode = "line";
                skip = 1;
              }
            else if ch == "/" && next == "*"
            then
              state
              // {
                out = state.out + "  ";
                mode = "block";
                depth = 1;
                skip = 1;
              }
            else if rawStart != null
            then
              state
              // {
                out = state.out + spaces rawStart.openerLength;
                mode = "raw";
                rawHashes = rawStart.hashes;
                skip = rawStart.openerLength - 1;
              }
            else if charLiteralLength > 0
            then
              state
              // {
                out = state.out + spaces charLiteralLength;
                skip = charLiteralLength - 1;
              }
            else if ch == "\""
            then
              state
              // {
                out = state.out + " ";
                mode = "string";
              }
            else
              state
              // {
                out = state.out + ch;
              }
          else if state.mode == "line"
          then
            if ch == "\n"
            then
              state
              // {
                out = state.out + "\n";
                mode = "code";
              }
            else
              state
              // {
                out = state.out + " ";
              }
          else if state.mode == "block"
          then
            if ch == "/" && next == "*"
            then
              state
              // {
                out = state.out + "  ";
                depth = state.depth + 1;
                skip = 1;
              }
            else if ch == "*" && next == "/"
            then
              state
              // {
                out = state.out + "  ";
                mode =
                  if state.depth == 1
                  then "code"
                  else "block";
                depth =
                  if state.depth == 1
                  then 0
                  else state.depth - 1;
                skip = 1;
              }
            else
              state
              // {
                out =
                  state.out
                  + (
                    if ch == "\n"
                    then "\n"
                    else " "
                  );
              }
          else if state.mode == "string"
          then
            if ch == "\\" && next != ""
            then
              state
              // {
                out =
                  state.out
                  + " "
                  + (
                    if next == "\n"
                    then "\n"
                    else " "
                  );
                skip = 1;
              }
            else if ch == "\""
            then
              state
              // {
                out = state.out + " ";
                mode = "code";
              }
            else
              state
              // {
                out =
                  state.out
                  + (
                    if ch == "\n"
                    then "\n"
                    else " "
                  );
              }
          else if state.mode == "raw"
          then
            if rawClosesAt state.rawHashes index
            then
              state
              // {
                out = state.out + spaces (state.rawHashes + 1);
                mode = "code";
                skip = state.rawHashes;
              }
            else
              state
              // {
                out =
                  state.out
                  + (
                    if ch == "\n"
                    then "\n"
                    else " "
                  );
              }
          else throw "invalid source scrubber state";
    in
      # Force the accumulated output flat before the next chunk so thunk
      # depth stays bounded by the longest line, not the whole file.
      builtins.seq (builtins.stringLength folded.out) folded;
    lines = lib.splitString "\n" content;
    lineCount = builtins.length lines;
    chunkAt = index:
      builtins.elemAt lines index
      + (
        if index + 1 < lineCount
        then "\n"
        else ""
      );
    result =
      builtins.foldl'
      (state: index: scrubChunk state (chunkAt index))
      {
        out = "";
        mode = "code";
        depth = 0;
        rawHashes = 0;
        skip = 0;
      }
      (builtins.genList (index: index) lineCount);
  in
    result.out;

  rustFilesUnder = relativeRoot: let
    absoluteRoot = root + "/${relativeRoot}";
    entries = builtins.readDir absoluteRoot;
  in
    lib.concatMap (
      name: let
        kind = entries.${name};
        relative = "${relativeRoot}/${name}";
      in
        if kind == "regular" && lib.hasSuffix ".rs" name
        then [relative]
        else if kind == "directory"
        then rustFilesUnder relative
        else []
    )
    (builtins.attrNames entries);

  lineCount = content:
    if content == ""
    then 0
    else let
      parts = lib.splitString "\n" content;
      raw = builtins.length parts;
    in
      if lib.hasSuffix "\n" content
      then raw - 1
      else raw;

  sourceLines = content: let
    parts = lib.splitString "\n" content;
  in
    if content != "" && lib.hasSuffix "\n" content
    then lib.init parts
    else parts;

  countCharacter = character: text:
    builtins.length (
      builtins.filter
      (index: builtins.substring index 1 text == character)
      (builtins.genList (index: index) (builtins.stringLength text))
    );

  isCfgTestLine = line: let
    normalized = lib.replaceStrings [" " "\t"] ["" ""] line;
    allPredicates =
      if lib.hasPrefix "#[cfg(all(" normalized && lib.hasSuffix "))]" normalized
      then
        lib.splitString "," (
          lib.removeSuffix "))]" (lib.removePrefix "#[cfg(all(" normalized)
        )
      else [];
  in
    normalized
    == "#[cfg(test)]"
    || builtins.elem "test" allPredicates;

  cfgTestLineMaskForScrubbed = scrubbed: let
    step = state: line: let
      cfgTest = isCfgTestLine line;
      active = state.active || cfgTest;
      trimmed = lib.trim line;
      stackedAttribute =
        state.active
        && !state.itemStarted
        && (state.attributeBrackets > 0 || lib.hasPrefix "#[" trimmed);
      blankBeforeItem = state.active && !state.itemStarted && trimmed == "";
      itemLine = active && !cfgTest && !stackedAttribute && !blankBeforeItem;

      attributeBrackets =
        if stackedAttribute
        then state.attributeBrackets + countCharacter "[" line - countCharacter "]" line
        else 0;
      parentheses =
        if itemLine || state.itemStarted
        then state.parentheses + countCharacter "(" line - countCharacter ")" line
        else 0;
      brackets =
        if itemLine || state.itemStarted
        then state.brackets + countCharacter "[" line - countCharacter "]" line
        else 0;
      braces =
        if itemLine || state.itemStarted
        then state.braces + countCharacter "{" line - countCharacter "}" line
        else 0;
      sawBracedBody =
        (itemLine || state.itemStarted)
        && (state.sawBracedBody || countCharacter "{" line > 0);
      itemStarted = state.itemStarted || itemLine;
      delimitersClosed = parentheses == 0 && brackets == 0 && braces == 0;
      unbracedTerminator =
        delimitersClosed
        && (hasInfix ";" line || lib.hasSuffix "," trimmed);
      itemComplete =
        itemStarted
        && (
          (sawBracedBody && delimitersClosed)
          || (!sawBracedBody && unbracedTerminator)
        );
    in
      if itemComplete
      then {
        active = false;
        itemStarted = false;
        attributeBrackets = 0;
        parentheses = 0;
        brackets = 0;
        braces = 0;
        sawBracedBody = false;
        mask = state.mask ++ [active];
      }
      else {
        inherit active itemStarted attributeBrackets parentheses brackets braces sawBracedBody;
        mask = state.mask ++ [active];
      };
  in
    (builtins.foldl' step {
      active = false;
      itemStarted = false;
      attributeBrackets = 0;
      parentheses = 0;
      brackets = 0;
      braces = 0;
      sawBracedBody = false;
      mask = [];
    } (sourceLines scrubbed)).mask;

  isTestOnlyPath = relative: let
    components = lib.splitString "/" relative;
    name = lib.last components;
  in
    builtins.any (component: builtins.elem component ["tests" "test_support"]) components
    || name == "tests.rs"
    || name == "test_support.rs"
    || lib.hasSuffix "_test.rs" name
    || lib.hasSuffix "_tests.rs" name
    || hasInfix "_test_" name;

  isTestSupportOnlyFrom = content: scrubbed: let
    source = sourceLines content;
    scrubbedSource = sourceLines scrubbed;
    classified =
      builtins.foldl' (
        state: index:
          if state.testOnly || !state.beforeItems
          then state
          else let
            scrubbedLine = lib.trim (builtins.elemAt scrubbedSource index);
            sourceLine = builtins.elemAt source index;
            normalized = lib.replaceStrings [" " "\t" "\r"] ["" "" ""] sourceLine;
            innerAttribute = lib.hasPrefix "#![" scrubbedLine;
            approvedTestAttribute =
              normalized
              == "#![cfg(test)]"
              || normalized == "#![cfg(any(test,feature=\"test-support\"))]";
          in
            if scrubbedLine == ""
            then state
            else if innerAttribute
            then
              state
              // {
                testOnly = approvedTestAttribute;
              }
            else
              state
              // {
                beforeItems = false;
              }
      ) {
        beforeItems = true;
        testOnly = false;
      } (builtins.genList (index: index) (builtins.length scrubbedSource));
  in
    classified.testOnly;

  isTestSupportOnly = content: let
    scrubbed = scrubCommentsAndStrings content;
  in
    isTestSupportOnlyFrom content scrubbed;

  sourceRoleLineCounts = relative: content: let
    total = lineCount content;
    scrubbed = scrubCommentsAndStrings content;
    testOnly = isTestOnlyPath relative || isTestSupportOnlyFrom content scrubbed;
    mask =
      if testOnly
      then builtins.genList (_: true) total
      else cfgTestLineMaskForScrubbed scrubbed;
    tests = builtins.length (builtins.filter (marked: marked) mask);
  in {
    implementation = total - tests;
    inherit tests;
  };

  reviewFor = relative: role:
    builtins.filter (entry: entry.path == relative && entry.role == role) sourceReviews;

  legacyLineCapAllows = relative: content:
    builtins.any (
      entry: entry.path == relative && lineCount content <= entry.maxLines
    )
    shapeLineDebt;

  sourceDigest = content: "sha256:${builtins.hashString "sha256" content}";

  sourceReviewFailuresForRole = relative: content: role: lines: let
    reviews = reviewFor relative role;
    reviewCount = builtins.length reviews;
    review =
      if reviewCount == 1
      then builtins.head reviews
      else null;
    grandfathered = legacyLineCapAllows relative content;
  in
    lib.optionals (reviewCount > 1) [
      "${relative}: duplicate source-review records for ${role}"
    ]
    ++ lib.optionals (lines <= responsibilityReviewThreshold && reviewCount != 0) [
      "${relative}: stale ${role} source review at ${builtins.toString lines} lines"
    ]
    ++ lib.optionals (lines > responsibilityReviewThreshold && !grandfathered && reviewCount == 0) [
      "${relative}: ${role} section has ${builtins.toString lines} lines and requires a content-bound responsibility review above ${builtins.toString responsibilityReviewThreshold}"
    ]
    ++ lib.optionals (lines > responsibilityReviewThreshold && review != null && review.digest != sourceDigest content) [
      "${relative}: ${role} source-review digest is stale"
    ]
    ++ lib.optionals (lines > responsibilityReviewThreshold && review != null && review.lines != lines) [
      "${relative}: ${role} source-review line count ${builtins.toString review.lines} does not match ${builtins.toString lines}"
    ]
    ++ lib.optionals (lines > cohesionReviewThreshold && review != null && review.cohesion == cohesionNotRequired) [
      "${relative}: ${role} section has ${builtins.toString lines} lines and requires a cohesion rationale above ${builtins.toString cohesionReviewThreshold}"
    ]
    ++ lib.optionals (lines > responsibilityReviewThreshold && lines <= cohesionReviewThreshold && review != null && review.cohesion != cohesionNotRequired) [
      "${relative}: ${role} source review must use `${cohesionNotRequired}` at ${builtins.toString lines} lines"
    ];

  sourceReviewFailures = relative: content: let
    counts = sourceRoleLineCounts relative content;
  in
    sourceReviewFailuresForRole relative content "implementation" counts.implementation
    ++ sourceReviewFailuresForRole relative content "tests" counts.tests;

  sourceShapeFailuresForContent = relative: content:
    lib.optionals (!(lib.hasPrefix "//!" content)) [
      "${relative}: missing `//!` module header"
    ];

  sourceShapeFailureAllowed = relative: content: finding:
    hasInfix "missing `//!` module header" finding
    && builtins.any (entry: entry.path == relative) shapeHeaderDebt;

  sourceShapeFailures = relative: let
    content = builtins.readFile (root + "/${relative}");
  in
    builtins.filter (finding: !(sourceShapeFailureAllowed relative content finding))
    (sourceShapeFailuresForContent relative content)
    ++ sourceReviewFailures relative content;

  # The Rust gate owns the scrubbed source-token boundary scan. Keeping that
  # character-level scanner in pure Nix makes this source-only mirror fragile on
  # generated-scale Rust files, so the Nix check enforces the manifest boundary
  # and leaves source-token precision to `engineering_hygiene.rs`.
  qemuBoundaryFailuresFor = package: relative: [];

  qemuTokenFailureAllowed = package: relative: finding:
    builtins.any (
      entry:
        entry.package
        == package
        && entry.path == relative
        && hasInfix "token `${entry.token}`" finding
    )
    qemuTokenDebt;

  dependencyPackageName = alias: value:
    if builtins.isAttrs value && value ? package
    then value.package
    else alias;

  dependencyPackagesInSection = scope: section: document: let
    table =
      if builtins.hasAttr section document
      then builtins.getAttr section document
      else {};
  in
    lib.mapAttrsToList (alias: value: {
      inherit scope;
      package = dependencyPackageName alias value;
    })
    table;

  manifestDependencyPackages = document:
    lib.concatMap (
      section: dependencyPackagesInSection section section document
    ) [
      "dependencies"
      "dev-dependencies"
      "build-dependencies"
    ]
    ++ lib.concatMap (
      target: let
        targetDocument = document.target.${target};
      in
        lib.concatMap (
          section:
            dependencyPackagesInSection "target.${target}.${section}" section targetDocument
        ) [
          "dependencies"
          "dev-dependencies"
          "build-dependencies"
        ]
    ) (
      if document ? target
      then builtins.attrNames document.target
      else []
    );

  qemuManifestFailuresForContent = package: relative: manifest:
    if builtins.elem package qemuBoundaryPackages
    then []
    else
      lib.concatMap (
        dependency:
          lib.optionals (builtins.elem dependency.package qemuBoundaryPackages) [
            "${relative}: QEMU boundary dependency `${dependency.package}` appears outside the QEMU boundary in `${package}` manifest section `${dependency.scope}`"
          ]
      ) (manifestDependencyPackages (builtins.fromTOML manifest));

  qemuManifestFailuresFor = package: relative: let
    findings = qemuManifestFailuresForContent package relative (builtins.readFile (root + "/${relative}"));
  in
    builtins.filter (finding: !(qemuManifestFailureAllowed package relative finding)) findings;

  qemuManifestFailureAllowed = package: relative: finding:
    builtins.any (
      entry:
        entry.package
        == package
        && entry.path == relative
        && hasInfix "dependency `${entry.dependency}`" finding
        && hasInfix "section `${entry.scope}`" finding
    )
    qemuManifestDebt;

  sourceShapeBaselineStaleFailures =
    lib.concatMap (
      entry: let
        exists = builtins.pathExists (root + "/${entry.path}");
        lines =
          if exists
          then lineCount (builtins.readFile (root + "/${entry.path}"))
          else 0;
      in
        lib.optionals (!exists) [
          "tests/crucible/engineering-hygiene-baseline.txt: shape-line path `${entry.path}` does not exist"
        ]
        ++ lib.optionals (exists && lines <= legacyShapeLineStaleThreshold) [
          "tests/crucible/engineering-hygiene-baseline.txt: stale shape-line baseline `${entry.path}` cap ${builtins.toString entry.maxLines} observed ${builtins.toString lines}"
        ]
    )
    shapeLineDebt
    ++ lib.concatMap (
      entry: let
        exists = builtins.pathExists (root + "/${entry.path}");
        content =
          if exists
          then builtins.readFile (root + "/${entry.path}")
          else "";
      in
        lib.optionals (!exists) [
          "tests/crucible/engineering-hygiene-baseline.txt: shape-header path `${entry.path}` does not exist"
        ]
        ++ lib.optionals (exists && lib.hasPrefix "//!" content) [
          "tests/crucible/engineering-hygiene-baseline.txt: stale shape-header baseline `${entry.path}`"
        ]
    )
    shapeHeaderDebt;

  validReviewDigest = digest:
    builtins.match "sha256:[0-9a-f]{64}" digest != null;

  sourceReviewKeys = map (entry: "${entry.path}|${entry.role}") sourceReviews;
  sourceReviewResponsibilities = map (entry: entry.responsibilities) sourceReviews;
  sourceReviewCohesion = map (entry: entry.cohesion) (
    builtins.filter (entry: entry.cohesion != cohesionNotRequired) sourceReviews
  );
  duplicateValues = values:
    builtins.filter (
      value: builtins.length (builtins.filter (candidate: candidate == value) values) > 1
    ) (lib.unique values);

  sourceReviewBaselineFailures =
    lib.concatMap (
      entry:
        lib.optionals (!(builtins.elem entry.role ["implementation" "tests"])) [
          "tests/crucible/engineering-hygiene-baseline.txt: source-review `${entry.path}` has invalid role `${entry.role}`"
        ]
        ++ lib.optionals (!(validReviewDigest entry.digest)) [
          "tests/crucible/engineering-hygiene-baseline.txt: source-review `${entry.path}` has invalid SHA-256 digest"
        ]
        ++ lib.optionals (entry.responsibilities == "" || entry.cohesion == "") [
          "tests/crucible/engineering-hygiene-baseline.txt: source-review `${entry.path}` has an empty rationale field"
        ]
        ++ lib.optionals (!(builtins.pathExists (root + "/${entry.path}"))) [
          "tests/crucible/engineering-hygiene-baseline.txt: source-review path `${entry.path}` does not exist"
        ]
    )
    sourceReviews
    ++ map (key: "tests/crucible/engineering-hygiene-baseline.txt: duplicate source-review `${key}`")
    (duplicateValues sourceReviewKeys)
    ++ map (responsibilities: "tests/crucible/engineering-hygiene-baseline.txt: source-review responsibilities are not file-specific: `${responsibilities}`")
    (duplicateValues sourceReviewResponsibilities)
    ++ map (cohesion: "tests/crucible/engineering-hygiene-baseline.txt: source-review cohesion rationale is not file-specific: `${cohesion}`")
    (duplicateValues sourceReviewCohesion);

  qemuManifestBaselineStaleFailures =
    lib.concatMap (
      entry: let
        findings = qemuManifestFailuresForContent entry.package entry.path (builtins.readFile (root + "/${entry.path}"));
      in
        lib.optionals (!(builtins.any (
            finding:
              hasInfix "dependency `${entry.dependency}`" finding
              && hasInfix "section `${entry.scope}`" finding
          )
          findings)) [
          "tests/crucible/engineering-hygiene-baseline.txt: stale qemu-manifest baseline `${entry.package}|${entry.path}|${entry.dependency}|${entry.scope}`"
        ]
    )
    qemuManifestDebt;

  packageSourceFailures = package: let
    files = rustFilesUnder "crates/${package}";
    implementationFiles = rustFilesUnder "crates/${package}/src";
  in
    lib.concatMap sourceShapeFailures files
    ++ lib.concatMap (qemuBoundaryFailuresFor package) implementationFiles
    ++ qemuManifestFailuresFor package "crates/${package}/Cargo.toml";

  commitRuleFailures = standards:
    lib.concatMap (
      rule:
        lib.concatMap (
          term:
            lib.optionals (!(hasInfix term standards)) [
              "STD-29 must document commit hygiene term `${term}`"
            ]
        )
        rule.terms
        ++ lib.optionals (!(hasInfix rule.id hygieneRust)) [
          "engineering_hygiene.rs must publish commit hygiene rule `${rule.id}`"
        ]
    )
    commitHygieneRules;

  standards = builtins.readFile ../../docs/rfcs/0010-crucible/28-engineering-standards.md;
  syntheticSource = lines:
    "//! synthetic\n"
    + builtins.concatStringsSep "" (
      builtins.genList (_: "fn line() {}\n") (lines - 1)
    );
  lineCountRegressionFailures = let
    syntheticPath = "crates/crucible-example/src/synthetic.rs";
    exactReview = sourceReviewFailures syntheticPath (syntheticSource responsibilityReviewThreshold);
    overReview = sourceReviewFailures syntheticPath (syntheticSource (responsibilityReviewThreshold + 1));
    mixed =
      "//! synthetic\n"
      + builtins.concatStringsSep "" (builtins.genList (_: "fn implementation() {}\n") 499)
      + "#[cfg(test)]\nmod tests {\n"
      + builtins.concatStringsSep "" (builtins.genList (_: "fn test_case() {}\n") 1197)
      + "}\n";
    mixedCounts = sourceRoleLineCounts syntheticPath mixed;
    testOnlyCounts = sourceRoleLineCounts "crates/crucible-example/src/tests.rs" (syntheticSource 1200);
    testSupportCounts = sourceRoleLineCounts "crates/crucible-example/src/node/test_support/large.rs" (syntheticSource 1200);
    testSupportModuleCounts = sourceRoleLineCounts "crates/crucible-example/src/test_support.rs" (syntheticSource 1200);
    stackedAttribute = ''
      //! synthetic
      #[cfg(test)]
      #[allow(dead_code, unused_variables)]
      fn gated(value: (u8, u8)) {
          let _ = value;
      }
      fn production() {}
    '';
    stackedCounts = sourceRoleLineCounts syntheticPath stackedAttribute;
    cfgField = ''
      //! synthetic
      struct Example {
          #[cfg(test)]
          #[allow(dead_code)]
          gated: Option<(u8, u8)>,
          production: u8,
      }
    '';
    cfgFieldCounts = sourceRoleLineCounts syntheticPath cfgField;
    cfgExpression = ''
      //! synthetic
      #[cfg(test)]
      let outcome = if condition {
          1
      } else {
          2
      };
      fn production() {}
    '';
    cfgExpressionCounts = sourceRoleLineCounts syntheticPath cfgExpression;
    fakeCrateCfg = ''
      //! synthetic
      const TEXT: &str = r###"
      #![cfg(test)]
      "quoted raw content"
      "###;
      /* #![cfg(test)] */
      fn production() {}
    '';
    realCrateCfg = ''
      #![cfg(any(test, feature = "test-support"))]
      //! synthetic
      fn support() {}
    '';
    platformOrTest = ''
      #![cfg(any(test, unix))]
      //! synthetic
      fn production() {}
    '';
    nestedCrateCfg = ''
      //! synthetic
      mod support {
          #![cfg(test)]
          fn nested() {}
      }
      fn production() {}
    '';
  in
    lib.optionals (exactReview != []) [
      "line-count regression: exact responsibility-review threshold should pass [${builtins.concatStringsSep "; " exactReview}]"
    ]
    ++ lib.optionals (!(builtins.any (finding: hasInfix "responsibility review above 1000" finding) overReview)) [
      "line-count regression: responsibility-review threshold + 1 should require review [${builtins.concatStringsSep "; " overReview}]"
    ]
    ++ lib.optionals (mixedCounts.implementation != 500 || mixedCounts.tests != 1200) [
      "line-count regression: co-located tests were not counted separately"
    ]
    ++ lib.optionals (testOnlyCounts.implementation != 0 || testOnlyCounts.tests != 1200) [
      "line-count regression: test-only source was not classified as tests"
    ]
    ++ lib.optionals (testSupportCounts.implementation != 0 || testSupportCounts.tests != 1200) [
      "line-count regression: nested test-support source was not classified as tests"
    ]
    ++ lib.optionals (testSupportModuleCounts.implementation != 0 || testSupportModuleCounts.tests != 1200) [
      "line-count regression: test-support module was not classified as tests"
    ]
    ++ lib.optionals (stackedCounts.implementation != 2 || stackedCounts.tests != 5) [
      "line-count regression: stacked attributes truncated a cfg(test) item"
    ]
    ++ lib.optionals (cfgFieldCounts.implementation != 4 || cfgFieldCounts.tests != 3) [
      "line-count regression: a cfg(test) field absorbed adjacent production fields"
    ]
    ++ lib.optionals (cfgExpressionCounts.implementation != 2 || cfgExpressionCounts.tests != 6) [
      "line-count regression: an else block truncated a cfg(test) expression"
    ]
    ++ lib.optionals (isTestSupportOnly fakeCrateCfg) [
      "line-count regression: a raw-string or comment payload impersonated a test-only crate attribute"
    ]
    ++ lib.optionals (!(isTestSupportOnly realCrateCfg)) [
      "line-count regression: the real test-support crate attribute was not recognized"
    ]
    ++ lib.optionals (isTestSupportOnly platformOrTest) [
      "line-count regression: a platform-or-test crate was misclassified as test-only"
    ]
    ++ lib.optionals (isTestSupportOnly nestedCrateCfg) [
      "line-count regression: a nested module attribute was misclassified as crate-level test-only"
    ];

  qemuManifestRegressionFailures = let
    rootManifest = ''
      [dependencies]
      vm_driver = { package = "crucible-qemu", path = "../crucible-qemu" }
    '';

    targetManifest = ''
      [target.'cfg(unix)'.dev-dependencies]
      plugin_driver = { package = "crucible-qemu-plugin", path = "../crucible-qemu-plugin" }
    '';
    rootRejected = qemuManifestFailuresForContent "crucible-session" "Cargo.toml" rootManifest;
    targetRejected = qemuManifestFailuresForContent "crucible-session" "Cargo.toml" targetManifest;
    allowed = qemuManifestFailuresForContent "crucible-qemu" "Cargo.toml" targetManifest;
  in
    lib.optionals (!(builtins.any (finding: hasInfix "QEMU boundary dependency" finding) rootRejected)) [
      "manifest regression: renamed root QEMU dependency should be rejected"
    ]
    ++ lib.optionals (!(builtins.any (finding: hasInfix "QEMU boundary dependency" finding) targetRejected)) [
      "manifest regression: renamed target QEMU dependency should be rejected"
    ]
    ++ lib.optionals (allowed != []) [
      "manifest regression: QEMU boundary package should be allowed [${builtins.concatStringsSep "; " allowed}]"
    ];

  sourceFailures =
    lib.concatMap packageSourceFailures cruciblePackages
    ++ sourceShapeBaselineStaleFailures
    ++ sourceReviewBaselineFailures
    ++ qemuManifestBaselineStaleFailures;
  policyFailures =
    commitRuleFailures standards
    ++ lib.optionals (!(hasInfix "engineeringHygiene = import ./phase1-engineering-hygiene.nix" defaultNix)) [
      "tests/crucible/default.nix must wire checks.crucible.phase1.engineeringHygiene"
    ]
    ++ lib.optionals (!(hasInfix "crateLayerGraph = import ./phase1-crate-layer-graph.nix" defaultNix)) [
      "tests/crucible/default.nix must keep the layer-boundary DAG check wired"
    ]
    ++ lib.optionals (!(builtins.pathExists ./phase1-crate-layer-graph.nix)) [
      "missing crate layer-graph mirror for STD-28"
    ]
    ++ lib.optionals (!(hasInfix "RESPONSIBILITY_REVIEW_LINE_THRESHOLD: usize = 1_000" hygieneRust)) [
      "engineering_hygiene.rs must publish the responsibility-review threshold"
    ]
    ++ lib.optionals (!(hasInfix "COHESION_REVIEW_LINE_THRESHOLD: usize = 1_500" hygieneRust)) [
      "engineering_hygiene.rs must publish the cohesion-review threshold"
    ]
    ++ lib.optionals (!(hasInfix "shape-review" hygieneRust)) [
      "engineering_hygiene.rs must consume content-bound source reviews"
    ]
    ++ lib.optionals (!(hasInfix "HygieneBaseline" hygieneRust)) [
      "engineering_hygiene.rs must consume the engineering hygiene baseline"
    ]
    ++ lib.optionals (!(hasInfix "stale_source_shape_failures" hygieneRust)) [
      "engineering_hygiene.rs must reject stale source-shape baseline entries"
    ]
    ++ lib.optionals (!(hasInfix "stale_qemu_token_failures" hygieneRust)) [
      "engineering_hygiene.rs must reject stale QEMU token baseline entries"
    ]
    ++ lib.optionals (!(hasInfix "stale_qemu_manifest_failures" hygieneRust)) [
      "engineering_hygiene.rs must reject stale QEMU manifest baseline entries"
    ];

  failures = sourceFailures ++ lineCountRegressionFailures ++ qemuManifestRegressionFailures ++ policyFailures;
  commitRuleSummary = builtins.concatStringsSep "," (map (rule: rule.id) commitHygieneRules);
in
  if failures != []
  then throw "crucible phase1 engineering hygiene lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-engineering-hygiene";
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
            check=checks.crucible.phase1.engineeringHygiene
            tasks=T-STD-11
            responsibility_review_threshold=1000
            cohesion_review_threshold=1500
            source_review_binding=whole-file-sha256-role-line-count
            layer_graph_check=checks.crucible.phase1.crateLayerGraph
            qemu_boundary=crucible-qemu,crucible-qemu-plugin
            debt_baseline=tests/crucible/engineering-hygiene-baseline.txt
            commit_hygiene_rules=${commitRuleSummary}
            RESULT
          '';
        }
      ];
    }
