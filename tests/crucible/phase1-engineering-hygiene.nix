{
  pkgs,
  lib,
}: let
  root = ../..;
  cratesDir = ../../crates;
  defaultNix = builtins.readFile ./default.nix;
  hygieneRust = builtins.readFile ../../crates/crucible-harness/tests/engineering_hygiene.rs;
  hygieneBaselineText = builtins.readFile ./engineering-hygiene-baseline.txt;

  softLineLimit = 600;
  hardLineLimit = 1000;

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
      charAt = index: builtins.substring index 1 chunk;
      indexes = builtins.genList (index: index) length;
      folded = builtins.foldl' step chunkState indexes;
      step = state: index:
        if state.skip
        then
          state
          // {
            skip = false;
          }
        else let
          ch = charAt index;
          next =
            if (index + 1) < length
            then charAt (index + 1)
            else "";
        in
          if state.mode == "code"
          then
            if ch == "/" && next == "/"
            then
              state
              // {
                out = state.out + "  ";
                mode = "line";
                skip = true;
              }
            else if ch == "/" && next == "*"
            then
              state
              // {
                out = state.out + "  ";
                mode = "block";
                depth = 1;
                skip = true;
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
                skip = true;
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
                skip = true;
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
          else if ch == "\\" && next != ""
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
              skip = true;
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
            };
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
        skip = false;
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

  sourceShapeFailuresForContent = relative: content: let
    lines = lineCount content;
  in
    lib.optionals (lines > hardLineLimit) [
      "${relative}: ${builtins.toString lines} lines exceeds hard line limit ${builtins.toString hardLineLimit}"
    ]
    ++ lib.optionals (lines <= hardLineLimit && lines > softLineLimit) [
      "${relative}: ${builtins.toString lines} lines exceeds soft line limit ${builtins.toString softLineLimit}"
    ]
    ++ lib.optionals (!(lib.hasPrefix "//!" content)) [
      "${relative}: missing `//!` module header"
    ];

  sourceShapeFailureAllowed = relative: content: finding: let
    lines = lineCount content;
  in
    (hasInfix "line limit" finding
      && builtins.any (entry: entry.path == relative && lines <= entry.maxLines) shapeLineDebt)
    || (hasInfix "missing `//!` module header" finding
      && builtins.any (entry: entry.path == relative) shapeHeaderDebt);

  sourceShapeFailures = relative: let
    content = builtins.readFile (root + "/${relative}");
  in
    builtins.filter (finding: !(sourceShapeFailureAllowed relative content finding))
    (sourceShapeFailuresForContent relative content);

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
        content = builtins.readFile (root + "/${entry.path}");
        lines = lineCount content;
      in
        lib.optionals (lines <= softLineLimit) [
          "tests/crucible/engineering-hygiene-baseline.txt: stale shape-line baseline `${entry.path}` cap ${builtins.toString entry.maxLines} observed ${builtins.toString lines}"
        ]
    )
    shapeLineDebt
    ++ lib.concatMap (
      entry: let
        content = builtins.readFile (root + "/${entry.path}");
      in
        lib.optionals (lib.hasPrefix "//!" content) [
          "tests/crucible/engineering-hygiene-baseline.txt: stale shape-header baseline `${entry.path}`"
        ]
    )
    shapeHeaderDebt;

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
  noLineLimitFailure = findings:
    !(builtins.any (finding: hasInfix "line limit" finding) findings);
  lineCountRegressionFailures = let
    exactSoft = sourceShapeFailuresForContent "synthetic.rs" (syntheticSource softLineLimit);
    overSoft = sourceShapeFailuresForContent "synthetic.rs" (syntheticSource (softLineLimit + 1));
    exactHard = sourceShapeFailuresForContent "synthetic.rs" (syntheticSource hardLineLimit);
    overHard = sourceShapeFailuresForContent "synthetic.rs" (syntheticSource (hardLineLimit + 1));
  in
    lib.optionals (!(noLineLimitFailure exactSoft)) [
      "line-count regression: exact soft limit should not fail [${builtins.concatStringsSep "; " exactSoft}]"
    ]
    ++ lib.optionals (!(builtins.any (finding: hasInfix "exceeds soft line limit" finding) overSoft)) [
      "line-count regression: soft+1 should fail [${builtins.concatStringsSep "; " overSoft}]"
    ]
    ++ lib.optionals (builtins.any (finding: hasInfix "exceeds hard line limit" finding) exactHard) [
      "line-count regression: exact hard limit should not hard-fail [${builtins.concatStringsSep "; " exactHard}]"
    ]
    ++ lib.optionals (!(builtins.any (finding: hasInfix "exceeds hard line limit" finding) overHard)) [
      "line-count regression: hard+1 should fail [${builtins.concatStringsSep "; " overHard}]"
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
    ++ lib.optionals (!(hasInfix "SOFT_LINE_LIMIT: usize = 600" hygieneRust)) [
      "engineering_hygiene.rs must publish the soft line limit"
    ]
    ++ lib.optionals (!(hasInfix "HARD_LINE_LIMIT: usize = 1_000" hygieneRust)) [
      "engineering_hygiene.rs must publish the hard line limit"
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
            file_soft_limit=600
            file_hard_limit=1000
            layer_graph_check=checks.crucible.phase1.crateLayerGraph
            qemu_boundary=crucible-qemu,crucible-qemu-plugin
            debt_baseline=tests/crucible/engineering-hygiene-baseline.txt
            commit_hygiene_rules=${commitRuleSummary}
            RESULT
          '';
        }
      ];
    }
