{
  pkgs,
  lib,
}: let
  root = ../..;
  cratesDir = ../../crates;
  defaultNix = builtins.readFile ./default.nix;
  hygieneRust = builtins.readFile ../../crates/crucible-harness/tests/engineering_hygiene.rs;

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
    "crucible"
    "crucible-session"
    "crucible-api"
    "crucible-daemon"
    "crucible-cli"
    "crucible-harness"
  ];
  qemuBoundaryPackages = ["crucible-qemu" "crucible-qemu-plugin"];
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

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  scrubCommentsAndStrings = content: let
    length = builtins.stringLength content;
    charAt = index: builtins.substring index 1 content;
    indexes = builtins.genList (index: index) length;
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
              out = state.out + (
                if ch == "\n"
                then "\n"
                else " "
              );
            }
        else if ch == "\\" && next != ""
        then
          state
          // {
            out = state.out + " " + (
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
            out = state.out + (
              if ch == "\n"
              then "\n"
              else " "
            );
          };
    result =
      builtins.foldl' step {
        out = "";
        mode = "code";
        depth = 0;
        skip = false;
      }
      indexes;
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

  sourceShapeFailures = relative:
    sourceShapeFailuresForContent relative (builtins.readFile (root + "/${relative}"));

  qemuBoundaryFailuresFor = package: relative:
    if builtins.elem package qemuBoundaryPackages
    then []
    else let
      content = scrubCommentsAndStrings (builtins.readFile (root + "/${relative}"));
    in
      lib.concatMap (
        token:
          lib.optionals (hasInfix token content) [
            "${relative}: QEMU-specific token `${token}` appears outside the QEMU boundary in `${package}`"
          ]
      )
      qemuSpecificTokens;

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

  qemuManifestFailuresFor = package: relative:
    qemuManifestFailuresForContent package relative (builtins.readFile (root + "/${relative}"));

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

  sourceFailures = lib.concatMap packageSourceFailures cruciblePackages;
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
            commit_hygiene_rules=${commitRuleSummary}
            RESULT
          '';
        }
      ];
    }
