{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase0.gates.harnessLint",
  dependencies ? [],
}: let
  allPackages = import ../../pkgs/tools/crucible/_packages.nix;
  workspaceManifest = builtins.readFile ../../crates/Cargo.toml;
  clippyConfig = builtins.readFile ../../crates/clippy.toml;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  assertionProperties = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  harnessLintBaseline = builtins.readFile ./harness-lint-baseline.txt;
  defaultChecks = builtins.readFile ./default.nix;
  crucibleModel = import ./_crucible-model-source.nix {inherit lib;};
  predicateDsl = builtins.readFile ../../crates/crucible/tests/predicate_dsl.rs;
  harnessLintMainRust = builtins.readFile ../../crates/crucible-harness/tests/harness_lint.rs;
  harnessLintScanRust = builtins.readFile ../../crates/crucible-harness/tests/support/harness_lint/scan.rs;
  harnessLintRust = builtins.concatStringsSep "\n" (
    [
      harnessLintMainRust
    ]
    ++ (map builtins.readFile [
      ../../crates/crucible-harness/tests/harness_lint_annotations.rs
      ../../crates/crucible-harness/tests/support/harness_lint/allow.rs
      ../../crates/crucible-harness/tests/support/harness_lint/clippy.rs
      ../../crates/crucible-harness/tests/support/harness_lint/common.rs
      ../../crates/crucible-harness/tests/support/harness_lint/confinement.rs
      ../../crates/crucible-harness/tests/support/harness_lint/error_logging.rs
      ../../crates/crucible-harness/tests/support/harness_lint/lex.rs
      ../../crates/crucible-harness/tests/support/harness_lint/reference_integrity.rs
    ])
    ++ [
      harnessLintScanRust
    ]
  );
  harnessLintMainCode = normalize harnessLintMainRust;
  harnessLintScanCode = normalize harnessLintScanRust;
  cruciblePackageNix = builtins.readFile ../../pkgs/tools/crucible/crucible.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  charAt = content: index: builtins.substring index 1 content;

  scrubRustContent = content: let
    length = builtins.stringLength content;
    chars =
      builtins.genList (
        index: let
          nextIndex = index + 1;
        in {
          ch = charAt content index;
          next =
            if nextIndex < length
            then charAt content nextIndex
            else "";
        }
      )
      length;
    spaceFor = ch:
      if ch == "\n"
      then "\n"
      else " ";
    step = state: item:
      if state.skip > 0
      then
        state
        // {
          skip = state.skip - 1;
        }
      else if state.mode == "code"
      then
        if item.ch == "/" && item.next == "/"
        then {
          mode = "line-comment";
          depth = state.depth;
          skip = 1;
          out = state.out + "  ";
        }
        else if item.ch == "/" && item.next == "*"
        then {
          mode = "block-comment";
          depth = 1;
          skip = 1;
          out = state.out + "  ";
        }
        else if item.ch == "\""
        then {
          mode = "string";
          depth = state.depth;
          skip = 0;
          out = state.out + " ";
        }
        else
          state
          // {
            out = state.out + item.ch;
          }
      else if state.mode == "line-comment"
      then
        if item.ch == "\n"
        then {
          mode = "code";
          depth = state.depth;
          skip = 0;
          out = state.out + "\n";
        }
        else
          state
          // {
            out = state.out + " ";
          }
      else if state.mode == "block-comment"
      then
        if item.ch == "/" && item.next == "*"
        then {
          mode = "block-comment";
          depth = state.depth + 1;
          skip = 1;
          out = state.out + "  ";
        }
        else if item.ch == "*" && item.next == "/"
        then {
          mode =
            if state.depth == 1
            then "code"
            else "block-comment";
          depth = state.depth - 1;
          skip = 1;
          out = state.out + "  ";
        }
        else
          state
          // {
            out = state.out + spaceFor item.ch;
          }
      else if item.ch == "\\" && item.next != ""
      then {
        mode = "string";
        depth = state.depth;
        skip = 1;
        out = state.out + " " + spaceFor item.next;
      }
      else if item.ch == "\""
      then {
        mode = "code";
        depth = state.depth;
        skip = 0;
        out = state.out + " ";
      }
      else
        state
        // {
          out = state.out + spaceFor item.ch;
        };
    final =
      builtins.foldl' step {
        mode = "code";
        depth = 0;
        skip = 0;
        out = "";
      }
      chars;
  in
    final.out;

  reductionPackages = [
    "crucible-sim"
    "crucible-assert"
    "crucible"
    "crucible-protocol"
    "crucible-device"
    "crucible-session"
  ];
  nondeterministicBoundaryPackages = ["crucible-daemon" "crucible-cli" "crucible-qemu"];
  binaryPackages = ["crucible-cli"];
  libraryPackages = builtins.filter (package: !(builtins.elem package binaryPackages)) allPackages;
  stateInfluencePatterns = [
    {
      pattern = "State";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "RuntimeState";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "Configuration";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "ScenarioDef";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "Schedule";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "Decision";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "QuantumRequest";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "QuantumOutcome";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "QuantumLoop";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "Backend";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "BackendInput";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "ExecutionHorizon";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "reduce";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "step";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "instantiate";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
    {
      pattern = "drive_quantum";
      reason = "host nondeterminism reaching State";
      rule = "host-nondeterminism-state";
    }
  ];
  stateRoutePatterns =
    (map (deny:
      deny
      // {
        reason = "host nondeterminism reaches API/session route";
      })
    stateInfluencePatterns)
    ++ [
      {
        pattern = "crucible_api";
        reason = "host nondeterminism reaches API/session route";
        rule = "host-nondeterminism-state";
      }
      {
        pattern = "crucible_session";
        reason = "host nondeterminism reaches API/session route";
        rule = "host-nondeterminism-state";
      }
      {
        pattern = "ControlClient";
        reason = "host nondeterminism reaches API/session route";
        rule = "host-nondeterminism-state";
      }
      {
        pattern = "SessionDriver";
        reason = "host nondeterminism reaches API/session route";
        rule = "host-nondeterminism-state";
      }
    ];
  publicExportNeedles = [
    "pubfn"
    "pubstruct"
    "pubenum"
    "pubtrait"
    "pubtype"
    "pubconst"
    "pubstatic"
    "pubmod"
    "pubuse"
    "pub(crate)fn"
    "pub(crate)struct"
    "pub(crate)enum"
    "pub(crate)trait"
    "pub(crate)type"
    "pub(crate)const"
    "pub(crate)static"
    "pub(crate)mod"
    "pub(crate)use"
  ];
  requiredClippyMethods = [
    "std::time::Instant::now"
    "std::time::Instant::elapsed"
    "std::time::SystemTime::now"
    "rand::thread_rng"
    "rand::rng"
    "rand::random"
    "getrandom::getrandom"
  ];
  requiredClippyTypes = [
    "std::collections::HashMap"
    "std::collections::HashSet"
    "std::collections::hash_map::DefaultHasher"
    "std::collections::hash_map::RandomState"
  ];
  requiredClippyDenyLints = [
    "all"
    "disallowed_methods"
    "disallowed_types"
    "expect_used"
    "float_arithmetic"
    "unwrap_used"
  ];

  denyPatterns = [
    {
      pattern = "std::time::SystemTime";
      reason = "host wall-clock";
      rule = "host-wall-clock";
    }
    {
      pattern = "SystemTime::now";
      reason = "host wall-clock";
      rule = "host-wall-clock";
    }
    {
      pattern = "std::time::Instant";
      reason = "host monotonic time";
      rule = "host-monotonic-time";
    }
    {
      pattern = "Instant::now";
      reason = "host monotonic time";
      rule = "host-monotonic-time";
    }
    {
      pattern = "rand::thread_rng";
      reason = "thread/global RNG";
      rule = "thread-global-rng";
    }
    {
      pattern = "thread_rng(";
      reason = "thread/global RNG";
      rule = "thread-global-rng";
    }
    {
      pattern = "rand::rng(";
      reason = "thread/global RNG";
      rule = "thread-global-rng";
    }
    {
      pattern = "StdRng::from_entropy";
      reason = "thread/global RNG";
      rule = "thread-global-rng";
    }
    {
      pattern = "SmallRng::from_entropy";
      reason = "thread/global RNG";
      rule = "thread-global-rng";
    }
    {
      pattern = "OsRng";
      reason = "host RNG";
      rule = "host-rng";
    }
    {
      pattern = "getrandom";
      reason = "host RNG";
      rule = "host-rng";
    }
    {
      pattern = "std::collections::HashMap";
      reason = "unordered map/set";
      rule = "unordered-map-set";
    }
    {
      pattern = "std::collections::HashSet";
      reason = "unordered map/set";
      rule = "unordered-map-set";
    }
    {
      pattern = "HashMap<";
      reason = "unordered map/set";
      rule = "unordered-map-set";
    }
    {
      pattern = "HashSet<";
      reason = "unordered map/set";
      rule = "unordered-map-set";
    }
    {
      pattern = "HashMap::";
      reason = "unordered map/set";
      rule = "unordered-map-set";
    }
    {
      pattern = "HashSet::";
      reason = "unordered map/set";
      rule = "unordered-map-set";
    }
    {
      pattern = "DefaultHasher";
      reason = "default/random hasher";
      rule = "default-random-hasher";
    }
    {
      pattern = "RandomState";
      reason = "default/random hasher";
      rule = "default-random-hasher";
    }
    {
      pattern = "tokio::select!";
      reason = "nondeterministic select";
      rule = "nondeterministic-select";
    }
    {
      pattern = "futures::select!";
      reason = "nondeterministic select";
      rule = "nondeterministic-select";
    }
    {
      pattern = "select!";
      reason = "nondeterministic select";
      rule = "nondeterministic-select";
    }
  ];

  productionDenyPatterns = [
    {
      pattern = ".unwrap(";
      reason = "panic shortcut";
      rule = "panic-shortcut";
    }
    {
      pattern = ".expect(";
      reason = "panic shortcut";
      rule = "panic-shortcut";
    }
  ];

  libraryDenyPatterns = [
    {
      pattern = "println!(";
      reason = "direct stdout/stderr diagnostic";
      rule = "direct-diagnostic";
    }
    {
      pattern = "eprintln!(";
      reason = "direct stdout/stderr diagnostic";
      rule = "direct-diagnostic";
    }
    {
      pattern = "print!(";
      reason = "direct stdout/stderr diagnostic";
      rule = "direct-diagnostic";
    }
    {
      pattern = "anyhow";
      reason = "erased error";
      rule = "erased-error";
    }
    {
      pattern = "eyre";
      reason = "erased error";
      rule = "erased-error";
    }
    {
      pattern = "miette";
      reason = "erased error";
      rule = "erased-error";
    }
    {
      pattern = "bail!(";
      reason = "erased error";
      rule = "erased-error";
    }
    {
      pattern = "dynError";
      reason = "erased error";
      rule = "erased-error";
    }
    {
      pattern = "dynstd::error::Error";
      reason = "erased error";
      rule = "erased-error";
    }
  ];
  listRustFiles = dir: let
    entries = builtins.readDir dir;
  in
    lib.concatMap (
      name: let
        kind = entries.${name};
        path = dir + "/${name}";
      in
        if kind == "directory"
        then listRustFiles path
        else if kind == "regular" && builtins.match ".*\\.rs" name != null
        then [path]
        else []
    ) (builtins.attrNames entries);

  scanNormalizedDenyPatterns = patterns: label: normalizedContent:
    lib.concatMap (
      deny:
        if hasInfix (normalize deny.pattern) normalizedContent
        then [
          "${label}: banned ${deny.reason} pattern `${deny.pattern}`"
        ]
        else []
    )
    patterns;

  denyRule = deny:
    if deny ? rule
    then deny.rule
    else "";

  hasLintAllowForLine = originalLines: lineIndex: rule: let
    line = lib.trim (builtins.elemAt originalLines (lineIndex - 1));
    prefix = "// crucible-lint: allow ${rule} -- ";
    prefixLength = builtins.stringLength prefix;
    rationale = builtins.substring prefixLength (builtins.stringLength line - prefixLength) line;
  in
    if rule == "" || lineIndex < 1
    then false
    else lib.hasPrefix prefix line && lib.trim rationale != "";

  normalizeSourceWithLines = content: let
    length = builtins.stringLength content;
    indexes = builtins.genList (i: i) length;
    step = state: index: let
      ch = charAt content index;
    in
      if ch == "\n"
      then
        state
        // {
          line = state.line + 1;
        }
      else if ch == " " || ch == "\t" || ch == "\r"
      then state
      else
        state
        // {
          text = state.text + ch;
          lines = state.lines ++ [state.line];
        };
  in
    builtins.foldl' step {
      text = "";
      lines = [];
      line = 0;
    }
    indexes;

  scanNormalizedDenyPatternsWithLines = patterns: label: content: let
    originalLines = lib.splitString "\n" content;
    normalizedSource = normalizeSourceWithLines (scrubRustContent content);
    normalizedContent = normalizedSource.text;
    normalizedLines = normalizedSource.lines;
  in
    lib.concatMap (
      deny: let
        normalizedPattern = normalize deny.pattern;
        patternLength = builtins.stringLength normalizedPattern;
        contentLength = builtins.stringLength normalizedContent;
        maxStart = contentLength - patternLength;
        indexes =
          if patternLength == 0 || maxStart < 0
          then []
          else builtins.genList (i: i) (maxStart + 1);
        rule = denyRule deny;
      in
        lib.concatMap (
          matchIndex: let
            lineIndex = builtins.elemAt normalizedLines matchIndex;
          in
            if builtins.substring matchIndex patternLength normalizedContent == normalizedPattern && !(hasLintAllowForLine originalLines lineIndex rule)
            then [
              "${label}:${builtins.toString (lineIndex + 1)}: banned ${deny.reason} pattern `${deny.pattern}`"
            ]
            else []
        )
        indexes
    )
    patterns;

  scanLineDenyPatterns = patterns: label: content: let
    originalLines = lib.splitString "\n" content;
    scrubbedLines = lib.splitString "\n" (scrubRustContent content);
    lineCount = builtins.length scrubbedLines;
  in
    lib.concatMap (
      lineIndex: let
        normalizedLine = normalize (builtins.elemAt scrubbedLines lineIndex);
      in
        lib.concatMap (
          deny: let
            rule = denyRule deny;
          in
            if hasInfix (normalize deny.pattern) normalizedLine && !(hasLintAllowForLine originalLines lineIndex rule)
            then [
              "${label}:${builtins.toString (lineIndex + 1)}: banned ${deny.reason} pattern `${deny.pattern}`"
            ]
            else []
        )
        patterns
    ) (builtins.genList (i: i) lineCount);

  scanDenyPatterns = patterns: label: content:
    scanNormalizedDenyPatternsWithLines patterns label content;

  scanManifestDenyPatterns = patterns: label: content:
    scanNormalizedDenyPatterns patterns label (normalize content);

  scanContent = scanDenyPatterns denyPatterns;

  missingFindingNeedles = findings: needles:
    builtins.filter (
      needle: !(builtins.any (finding: hasInfix needle finding) findings)
    )
    needles;

  scanProductionContent = label: content:
    scanDenyPatterns productionDenyPatterns label content;

  scanStringlyErrorContent = label: content: let
    originalLines = lib.splitString "\n" content;
    normalizedSource = normalizeSourceWithLines (scrubRustContent content);
    normalizedContent = normalizedSource.text;
    normalizedLines = normalizedSource.lines;
    resultPattern = "Result<";
    resultPatternLength = builtins.stringLength resultPattern;
    contentLength = builtins.stringLength normalizedContent;
    maxStart = contentLength - resultPatternLength;
    indexes =
      if maxStart < 0
      then []
      else builtins.genList (i: i) (maxStart + 1);
  in
    lib.concatMap (
      matchIndex: let
        lineIndex = builtins.elemAt normalizedLines matchIndex;
        tail = builtins.substring matchIndex (contentLength - matchIndex) normalizedContent;
      in
        if builtins.substring matchIndex resultPatternLength normalizedContent == resultPattern && hasInfix ",String>" tail && !(hasLintAllowForLine originalLines lineIndex "stringly-error")
        then [
          "${label}:${builtins.toString (lineIndex + 1)}: banned stringly error pattern `Result<_, String>`"
        ]
        else []
    )
    indexes;

  scanLibraryContent = label: content:
    scanDenyPatterns libraryDenyPatterns label content
    ++ scanStringlyErrorContent label content;

  scanErrorLoggingContent = label: isBinaryBoundary: content:
    scanDenyPatterns productionDenyPatterns label content
    ++ lib.optionals (!isBinaryBoundary) (scanLibraryContent label content);

  scanStateInfluenceContent = label: content:
    scanDenyPatterns stateInfluencePatterns label content;

  scanBoundaryRouteContent = label: content:
    scanDenyPatterns stateRoutePatterns label content;

  scanPublicExportContent = label: content: let
    normalizedContent = normalize (scrubRustContent content);
  in
    lib.concatMap (
      needle:
        lib.optionals (hasInfix needle normalizedContent) [
          "${label}: banned public export from nondeterministic boundary source pattern `${needle}`"
        ]
    )
    publicExportNeedles;

  isBinaryBoundarySource = package: path:
    (package == "crucible-cli" && lib.hasPrefix (toString (../../crates + "/crucible-cli/src/")) (toString path))
    || hasInfix "/src/bin/" (toString path);

  sourceDeclaresTypedError = content: let
    normalizedContent = normalize (scrubRustContent content);
  in
    hasInfix "implErrorfor" normalizedContent
    || hasInfix "implstd::error::Errorfor" normalizedContent
    || hasInfix "derive(Error" normalizedContent;

  scanManifestErrorPolicyContent = label: manifest: sourceContents: let
    normalizedManifest = normalize manifest;
    hasTypedError =
      hasInfix "thiserror=" normalizedManifest
      || builtins.any sourceDeclaresTypedError sourceContents;
  in
    scanManifestDenyPatterns [
      {
        pattern = "anyhow";
        reason = "erased error dependency";
      }
      {
        pattern = "eyre";
        reason = "erased error dependency";
      }
      {
        pattern = "miette";
        reason = "erased error dependency";
      }
    ]
    label
    manifest
    ++ lib.optionals (!hasTypedError) [
      "${label}: missing typed error signal `thiserror` dependency or `impl Error for ...`"
    ];

  manifestErrorPolicyFailures = package: let
    sourceContents = map builtins.readFile (listRustFiles (../../crates + "/${package}/src"));
  in
    scanManifestErrorPolicyContent
    "${package}/Cargo.toml"
    (builtins.readFile (../../crates + "/${package}/Cargo.toml"))
    sourceContents;

  readManifest = package: builtins.fromTOML (builtins.readFile (../../crates + "/${package}/Cargo.toml"));

  workspaceManifestToml = builtins.fromTOML workspaceManifest;
  workspaceDependencies =
    if workspaceManifestToml ? workspace && workspaceManifestToml.workspace ? dependencies
    then workspaceManifestToml.workspace.dependencies
    else {};

  dependencyPackageName = workspaceDeps: name: value:
    if builtins.isAttrs value && value ? workspace && value.workspace == true
    then
      if builtins.hasAttr name workspaceDeps && builtins.isAttrs workspaceDeps.${name} && workspaceDeps.${name} ? package
      then workspaceDeps.${name}.package
      else name
    else if builtins.isAttrs value && value ? package
    then value.package
    else name;

  dependencySpecs = workspaceDeps: manifest: let
    dependencyTableSpecs = scope: dependencies:
      lib.mapAttrsToList (name: value: {
        inherit name scope;
        package = dependencyPackageName workspaceDeps name value;
      })
      dependencies;
    direct =
      if manifest ? dependencies
      then dependencyTableSpecs "dependencies" manifest.dependencies
      else [];
    target =
      if manifest ? target
      then
        lib.concatMap (
          targetName: let
            targetSpec = manifest.target.${targetName};
          in
            if targetSpec ? dependencies
            then dependencyTableSpecs "target.${targetName}.dependencies" targetSpec.dependencies
            else []
        ) (builtins.attrNames manifest.target)
      else [];
  in
    direct ++ target;

  boundaryManifestFailuresFor = workspaceDeps: package: manifest:
    if builtins.elem package ["crucible-cli" "crucible-qemu"]
    then []
    else
      lib.concatMap (
        dependency:
          lib.optionals (dependency.package == "crucible") [
            "${package}: dependency `${dependency.name}` in ${dependency.scope} may route host nondeterminism directly into engine State"
          ]
      )
      (dependencySpecs workspaceDeps manifest);

  normalize = builtins.replaceStrings [" " "\t" "\n" "\r"] ["" "" "" ""];

  strictDeterministicPackages = builtins.filter (package: !(builtins.elem package nondeterministicBoundaryPackages)) allPackages;

  relativeSourcePath = package: path: let
    prefix = toString (../../crates + "/${package}/");
    full = toString path;
  in
    builtins.substring (builtins.stringLength prefix) (builtins.stringLength full - builtins.stringLength prefix) full;

  packageSourceEntries = package:
    map (path: {
      inherit package path;
      relative = relativeSourcePath package path;
      label = toString path;
      content = builtins.readFile path;
    })
    (listRustFiles (../../crates + "/${package}/src"));

  relativeIsUnder = relative: prefix:
    relative == "${prefix}.rs" || lib.hasPrefix "${prefix}/" relative;

  boundarySourceAllowsHostNondeterminism = package: relative:
    if package == "crucible-cli"
    then
      relative
      == "src/main.rs"
      || relativeIsUnder relative "src/diagnostics"
      || relativeIsUnder relative "src/output"
      || relativeIsUnder relative "src/progress"
    else if package == "crucible-daemon"
    then
      relativeIsUnder relative "src/diagnostics"
      || relativeIsUnder relative "src/supervision"
      || relativeIsUnder relative "src/transport"
    else if package == "crucible-qemu"
    then
      relativeIsUnder relative "src/diagnostics"
      || relativeIsUnder relative "src/process"
      || relativeIsUnder relative "src/supervision"
    else false;

  nonBoundarySourceFailures = source:
    map (finding: "${finding}; package `${source.package}` is not a host-nondeterminism boundary")
    (scanContent source.label source.content);

  boundaryPackageSourceFailures = package: sources: let
    nondeterministicSources = builtins.filter (source: scanContent source.label source.content != []) sources;
    hasNondeterminism = nondeterministicSources != [];
    pathFailures =
      lib.concatMap (
        source:
          lib.optionals (!(boundarySourceAllowsHostNondeterminism package source.relative))
          (map (finding: "${finding}; host nondeterminism outside supervision/diagnostics path")
            (scanContent source.label source.content))
      )
      nondeterministicSources;
    exportFailures =
      lib.concatMap (
        source:
          scanPublicExportContent source.label source.content
      )
      nondeterministicSources;
    routeFailures =
      lib.optionals hasNondeterminism
      (lib.concatMap (
          source:
            scanBoundaryRouteContent source.label source.content
        )
        sources);
    stateFailures =
      lib.optionals hasNondeterminism
      (lib.concatMap (
          source:
            scanStateInfluenceContent source.label source.content
        )
        sources);
  in
    pathFailures ++ exportFailures ++ routeFailures ++ stateFailures;

  # The full-source scans below are executed by the Rust harness in pkgs.crucible.
  # Keeping the same whole-workspace scanner in Nix eval overflows the evaluator
  # as the Crucible workspace grows, so the Nix gate keeps only synthetic
  # scanner regressions plus wiring/completion evidence.
  sourceFailures = [];

  boundarySourceFailures = [];

  boundaryManifestFailures =
    lib.concatMap (
      package:
        boundaryManifestFailuresFor workspaceDependencies package (readManifest package)
    )
    nondeterministicBoundaryPackages;

  productionSourceFailures = [];

  manifestFailures = [];

  clippyTierFailures = let
    normalizedWorkspaceManifest = normalize workspaceManifest;
    normalizedClippyConfig = normalize clippyConfig;
    normalizedCruciblePackageNix = normalize cruciblePackageNix;
    workspaceDenyFailures =
      lib.concatMap (
        lint:
          lib.optionals (!(hasInfix "${lint}=\"deny\"" normalizedWorkspaceManifest)) [
            "crates/Cargo.toml: missing workspace clippy deny `${lint} = \"deny\"`"
          ]
      )
      requiredClippyDenyLints;
    methodFailures =
      lib.concatMap (
        method:
          lib.optionals (!(hasInfix "path=\"${method}\"" normalizedClippyConfig)) [
            "crates/clippy.toml: missing disallowed method `${method}`"
          ]
      )
      requiredClippyMethods;
    typeFailures =
      lib.concatMap (
        disallowedType:
          lib.optionals (!(hasInfix "path=\"${disallowedType}\"" normalizedClippyConfig)) [
            "crates/clippy.toml: missing disallowed type `${disallowedType}`"
          ]
      )
      requiredClippyTypes;
    manifestFailures =
      lib.concatMap (
        package: let
          normalizedManifest = normalize (builtins.readFile (../../crates + "/${package}/Cargo.toml"));
        in
          lib.optionals (!(hasInfix "[lints]workspace=true" normalizedManifest)) [
            "${package}/Cargo.toml: missing workspace lint inheritance"
          ]
      )
      allPackages;
    buildHookFailures =
      lib.concatMap (
        required:
          lib.optionals (!(hasInfix required normalizedCruciblePackageNix)) [
            "pkgs/tools/crucible/crucible.nix: missing clippy gate wiring `${required}`"
          ]
      ) [
        "cargoclippy"
        "--all-targets"
        "rust.dev"
        "-Dwarnings"
        "workspaceCargoFlags"
      ];
  in
    workspaceDenyFailures ++ methodFailures ++ typeFailures ++ manifestFailures ++ buildHookFailures;

  customStaticTierFailures = let
    requiredRustTierText = [
      "custom_static_analysis_tier_runs_over_crucible_sources"
      "for spec in crate_spec_index()"
      "package_dir.join(\"src\")"
      "custom_static_analysis_failures"
      "hash_container_iteration_failures"
      "default_random_hasher_failures"
      "default/random hasher"
      "default-random-hasher"
      "unordered_select_failures"
      "select_macro_is_unordered"
      "bare_unsafe_block_failures"
      "has_adjacent_safety_comment"
      "HASH_ITERATION_METHODS"
      "\"iter_mut\""
      "\"values_mut\""
      "\"into_keys\""
      "\"into_values\""
      "\"biased\""
      "stale_safety_findings"
      "allow_annotations_are_checked_for_all_crucible_targets"
      "harness_lint_enforces_annotated_exceptions"
      "LINT_ALLOW_PREFIX"
      "LINT_RULES"
      "allow_annotation_failures"
      "has_lint_allow_in_preceding_marker_block"
      "allow_attribute_rule"
      "attribute_text"
      "clippy-disallowed-type"
      "clippy-disallowed-method"
      "mismatched_allow"
      "same_line_unannotated_allow"
      "multiline_preceding_same_line_allow"
      "multi_rule_missing_allow"
      "multi_rule_annotated_allow"
      "compact_marker_allow"
      "token_spaced_allow"
      "newline_spaced_allow"
      "trailing_marker_allow"
      "error_logging_allowed"
      "multiline_mismatched_allow"
      "multiline_cfg_attr_allow"
      "split_head_mismatched_allow"
      "split_head_annotated_allow"
      "cfg_attr(test, allow(clippy::disallowed_methods))"
      "malformed crucible-lint allow"
      "unannotated allow"
      "#[allow(clippy::disallowed_types)]"
      "host_boundary_nondeterminism_is_confined_from_state"
      "harness_lint_rejects_host_boundary_state_leaks"
      "workspace_confinement_findings"
      "package_source_confinement_findings"
      "confinement_regression_failures"
      "non_boundary_source_findings"
      "boundary_source_allows_host_nondeterminism"
      "public_export_findings"
      "route_ingress_findings"
      "boundary_manifest_findings"
      "NONDETERMINISTIC_BOUNDARY_PACKAGES"
      "STATE_INFLUENCE_IDENTIFIERS"
      "STATE_ROUTE_IDENTIFIERS"
      "host-nondeterminism-state"
      "may not route host nondeterminism"
      "not a host-nondeterminism boundary"
      "outside supervision/diagnostics path"
      "public export from nondeterministic boundary source"
      "DISTRIBUTION_METADATA_IDENTIFIERS"
      "DISTRIBUTION_METADATA_FLOW_TARGETS"
      "DISTRIBUTION_METADATA_COORDINATION_ONLY_TARGETS"
      "DISTRIBUTION_METADATA_COORDINATION_FUNCTION_TERMS"
      "distribution_metadata_flow_failures"
      "distribution_metadata_identifier_is_guarded"
      "distribution_metadata_function_is_coordination_only"
      "claim_replay_artifact"
      "progress_reduce"
      "distribution-metadata-flow"
      "harness_lint_rejects_distribution_metadata_in_identity_paths"
      "harness_lint_allows_distribution_metadata_in_coordination_paths"
      "distribution metadata reaching reduce/Decision/content key/artifact path"
      "gate_evidence_references_are_integral"
      "gate_reference_integrity_failures"
      "task_metadata_state_failures"
      "completed RFC task"
      "open RFC task"
    ];
    rustTierFailures =
      lib.concatMap (
        required:
          lib.optionals (!(hasInfix required harnessLintRust)) [
            "crates/crucible-harness/tests/harness_lint.rs: missing custom static-analysis tier wiring `${required}`"
          ]
      )
      requiredRustTierText;
    packageHookFailures =
      lib.optionals (!(
        hasInfix "doCheck=true" (normalize cruciblePackageNix)
        && hasInfix "cargoTestFlags=" (normalize cruciblePackageNix)
        && hasInfix "--featurescrucible-cli/test-double" (normalize cruciblePackageNix)
      )) [
        "pkgs/tools/crucible/crucible.nix: missing package test hook for Rust custom static-analysis tier"
      ];
  in
    rustTierFailures ++ packageHookFailures;

  regressionFailures = let
    findings = scanContent "regression.rs" ''
      fn bad() {
        let _ = std::time::SystemTime::now();
        let _ = rand::thread_rng();
        let _ = std::collections::HashMap::<u8, u8>::new();
        let _ = std::collections::hash_map::DefaultHasher::new();
        tokio::select! { _ = async {} => {} }
      }
    '';
    missing = missingFindingNeedles findings [
      "host wall-clock"
      "thread/global RNG"
      "unordered map/set"
      "default/random hasher"
      "nondeterministic select"
    ];
  in
    if missing == []
    then []
    else [
      "harness-lint regression missing expected findings: ${builtins.concatStringsSep ", " missing}"
    ];

  spacedPathRegressionFailures = let
    findings = scanContent "spaced-regression.rs" ''
      use std::collections::{HashMap, HashSet};
      use std::collections::hash_map::{DefaultHasher, RandomState};
      use std::time::{Instant, SystemTime};

      fn bad() {
        let _ = HashMap :: <u8, u8> :: new();
        let _ = HashSet :: <u8> :: new();
        let _ = DefaultHasher :: new();
        let _ = RandomState :: new();
        let _ = SystemTime :: now();
        let _ = Instant :: now();
        rand :: thread_rng();
        rand :: rng();
        tokio::select ! { _ = async {} => {} }
      }
    '';
    missing = missingFindingNeedles findings [
      "host wall-clock"
      "host monotonic time"
      "thread/global RNG"
      "unordered map/set"
      "default/random hasher"
      "nondeterministic select"
    ];
  in
    if missing == []
    then []
    else [
      "harness-lint regression failed to reject spaced paths and grouped imports: ${builtins.concatStringsSep ", " missing}"
    ];

  scrubRegressionFailures = let
    findings = scanContent "scrub-regression.rs" ''
      //! std::time::SystemTime::now()
      // rand::thread_rng()
      /*
        std::collections::HashMap::<u8, u8>::new()
      */
      const TEXT: &str = "tokio::select!";
    '';
  in
    if findings == []
    then []
    else [
      "harness-lint regression failed to ignore comments and strings"
    ];

  errorLoggingRegressionFailures = let
    libraryFindings = scanErrorLoggingContent "library-regression.rs" false ''
      pub fn bad() -> Result<(), Box<dyn Error>> {
        maybe().unwrap();
        maybe().expect /* comment */ ("value exists");
        println!("library diagnostic");
        eprintln!("library diagnostic");
        print!("library diagnostic");
        anyhow::bail!("erased error");
      }
    '';
    cliBoundaryFindings = scanErrorLoggingContent "crucible-cli/src/main.rs" true ''
      fn main() -> anyhow::Result<()> {
        println!("cli output is allowed");
        Ok(())
      }
    '';
    cliModuleFindings = scanErrorLoggingContent "crucible-cli/src/command.rs" true ''
      pub fn command() -> anyhow::Result<()> {
        println!("command module output crosses the binary boundary");
        Ok(())
      }
    '';
  in
    lib.optionals (builtins.length libraryFindings < 6) [
      "harness-lint regression failed to reject error/logging drift"
    ]
    ++ lib.optionals (cliBoundaryFindings != []) [
      "harness-lint regression incorrectly rejected CLI boundary output"
    ]
    ++ lib.optionals (cliModuleFindings != []) [
      "harness-lint regression incorrectly rejected CLI module boundary output"
    ];

  manifestRegressionFailures = let
    erasedFindings = scanManifestErrorPolicyContent "crucible-sim/Cargo.toml" ''
      [dependencies]
      thiserror = { workspace = true }
      anyhow = { workspace = true }
    '' [];
    missingTypedFindings = scanManifestErrorPolicyContent "crucible-sim/Cargo.toml" ''
      [dependencies]
    '' [];
    handRolledFindings =
      scanManifestErrorPolicyContent "crucible-harness/Cargo.toml" ''
        [dependencies]
      '' [
        ''
          use std::error::Error;

          pub struct HarnessError;

          impl Error for HarnessError {}
        ''
      ];
  in
    if erasedFindings != [] && missingTypedFindings != [] && handRolledFindings == []
    then []
    else [
      "harness-lint regression failed to reject manifest error policy drift"
    ];

  exceptionPolicyRegressionFailures = let
    allowedFindings = scanContent "allowed-exception.rs" ''
      fn allowed() {
        // crucible-lint: allow unordered-map-set -- synthetic pure lookup cache, order never escapes
        let _map: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
      }
    '';
    unannotatedFindings = scanContent "unannotated-exception.rs" ''
      fn bad() {
        let _map: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
      }
    '';
    malformedFindings = scanContent "malformed-exception.rs" ''
      fn bad() {
        // crucible-lint: allow unordered-map-set --
        let _map: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
      }
    '';
    malformedSyntaxFindings = scanContent "malformed-syntax-exception.rs" ''
      fn bad() {
        //crucible-lint:allow unordered-map-set--synthetic rationale with invalid marker syntax
        let _map: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
      }
    '';
    wrongRuleFindings = scanContent "wrong-rule-exception.rs" ''
      fn bad() {
        // crucible-lint: allow host-wall-clock -- wrong rule for this hash-map exception
        let _map: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
      }
    '';
    multilineFindings = scanContent "multiline-exception.rs" ''
      fn bad() {
        let _map: std::collections::
          HashMap
          <u8, u8> = std::collections::
          HashMap
          ::new();
      }
    '';
    stringlyAllowedFindings = scanErrorLoggingContent "stringly-allowed.rs" false ''
      fn allowed() {
        // crucible-lint: allow stringly-error -- synthetic string error is isolated to this regression sample
        let _value: Result<(), String> = Ok(());
      }
    '';
    defaultHasherAllowedFindings = scanContent "default-hasher-allowed.rs" ''
      fn allowed() {
        // crucible-lint: allow default-random-hasher -- synthetic fixture proves annotated exceptions for non-identity hashing
        let _hasher = std::collections::hash_map::DefaultHasher::new();
      }
    '';
    defaultHasherUnannotatedFindings = scanContent "default-hasher-unannotated.rs" ''
      fn bad() {
        let _hasher = std::collections::hash_map::DefaultHasher::new();
      }
    '';
    stringlyUnannotatedFindings = scanErrorLoggingContent "stringly-unannotated.rs" false ''
      fn bad() {
        let _value: Result<(), String> = Ok(());
      }
    '';
  in
    if allowedFindings == [] && unannotatedFindings != [] && malformedFindings != [] && malformedSyntaxFindings != [] && wrongRuleFindings != [] && multilineFindings != [] && stringlyAllowedFindings == [] && stringlyUnannotatedFindings != [] && defaultHasherAllowedFindings == [] && defaultHasherUnannotatedFindings != []
    then []
    else [
      "harness-lint regression failed to enforce annotated exception policy"
    ];

  confinementRegressionFailures = let
    source = package: relative: content: {
      inherit package relative content;
      label = "${package}/${relative}";
    };
    sameFileFindings = boundaryPackageSourceFailures "crucible-cli" [
      (source "crucible-cli" "src/main.rs" ''
        use crucible::State;

        fn bad() {
          let stamp = std::time::SystemTime::now();
          let _state: Option<State> = None;
          consume(stamp);
        }
      '')
    ];
    splitModuleFindings = boundaryPackageSourceFailures "crucible-cli" [
      (source "crucible-cli" "src/main.rs" ''
        fn host_stamp() {
          let stamp = std::time::SystemTime::now();
          consume(stamp);
        }
      '')
      (source "crucible-cli" "src/session.rs" ''
        use crucible_session::SessionDriver;
        use crucible_api::ControlClient;

        fn route(client: ControlClient, driver: SessionDriver<()>) {
          submit(client, driver);
        }
      '')
    ];
    apiFindings = nonBoundarySourceFailures (source "crucible-api" "src/lib.rs" ''
      fn bad() {
        let stamp = std::time::SystemTime::now();
        consume(stamp);
      }
    '');
    qemuBackendFindings = boundaryPackageSourceFailures "crucible-qemu" [
      (source "crucible-qemu" "src/backend.rs" ''
        fn bad() {
          let stamp = std::time::SystemTime::now();
          consume(stamp);
        }
      '')
    ];
    qemuSupervisionFindings = boundaryPackageSourceFailures "crucible-qemu" [
      (source "crucible-qemu" "src/supervision/process.rs" ''
        fn diagnostic_timestamp() {
          let stamp = std::time::SystemTime::now();
          eprintln!("{stamp:?}");
        }
      '')
    ];
    publicExportFindings = boundaryPackageSourceFailures "crucible-daemon" [
      (source "crucible-daemon" "src/supervision.rs" ''
        pub(crate) fn host_timestamp() {
          let stamp = std::time::SystemTime::now();
          consume(stamp);
        }
      '')
    ];
    directManifestFindings = boundaryManifestFailuresFor {} "crucible-daemon" {
      dependencies.engine = {
        package = "crucible";
      };
    };
    workspaceManifestFindings =
      boundaryManifestFailuresFor {
        engine = {
          package = "crucible";
        };
      } "crucible-daemon" {
        dependencies.engine = {
          workspace = true;
        };
      };
  in
    lib.optionals (sameFileFindings == []) [
      "harness-lint confinement regression failed to reject same-file State ingress"
    ]
    ++ lib.optionals (splitModuleFindings == []) [
      "harness-lint confinement regression failed to reject split-module State ingress"
    ]
    ++ lib.optionals (apiFindings == []) [
      "harness-lint confinement regression failed to reject nondeterminism outside boundary crates"
    ]
    ++ lib.optionals (qemuBackendFindings == []) [
      "harness-lint confinement regression failed to reject qemu reduction-path nondeterminism"
    ]
    ++ lib.optionals (qemuSupervisionFindings != []) [
      "harness-lint confinement regression incorrectly rejected qemu supervision diagnostics"
    ]
    ++ lib.optionals (publicExportFindings == []) [
      "harness-lint confinement regression failed to reject exported host values"
    ]
    ++ lib.optionals (directManifestFindings == []) [
      "harness-lint confinement regression failed to reject direct engine dependency"
    ]
    ++ lib.optionals (workspaceManifestFindings == []) [
      "harness-lint confinement regression failed to reject workspace engine alias"
    ];

  tDet17CompletionFailures = let
    requiredHarnessCode = [
      "fn reduction_path_sources_have_no_banned_nondeterminism() -> Result<(), Box<dyn Error>>"
      "for package in REDUCTION_PATH_PACKAGES"
      "findings.extend(scan_content(&source, &content));"
      "fn host_boundary_nondeterminism_is_confined_from_state() -> Result<(), Box<dyn Error>>"
      "workspace_confinement_findings(&root, &workspace_dependencies)"
      "HarnessLintBaseline::load(&repo)"
      "filter_findings("
      "stale {category} baseline"
      "fn clippy_tier_is_checked_in_and_wired() -> Result<(), Box<dyn Error>>"
      "clippy_tier_failures("
      "fn custom_static_analysis_tier_runs_over_crucible_sources() -> Result<(), Box<dyn Error>>"
      "for spec in crate_spec_index()"
      "custom_static_analysis_failures(&source, &content)"
      "fn harness_lint_rejects_banned_code_patterns()"
      "fn harness_lint_rejects_spaced_paths_and_grouped_imports()"
      "hash_container_iteration_failures"
      "unordered_select_failures"
      "select_macro_is_unordered"
      "HASH_ITERATION_METHODS"
    ];
    requiredDenyCoverage = [
      {
        reason = "host wall-clock";
        rule = "host-wall-clock";
      }
      {
        reason = "thread/global RNG";
        rule = "thread-global-rng";
      }
      {
        reason = "unordered map/set";
        rule = "unordered-map-set";
      }
      {
        reason = "default/random hasher";
        rule = "default-random-hasher";
      }
      {
        reason = "nondeterministic select";
        rule = "nondeterministic-select";
      }
    ];
    requiredDefaultCheckBlocks = [
      {
        label = "phase0 gate:harness-lint attr path";
        text = ''attrPath = "checks.crucible.phase0.gates.harnessLint";'';
      }
      {
        label = "phase0 gate:harness-lint import";
        text = "gate = import ./phase1-harness-lint.nix";
      }
      {
        label = "phase1 gate:harness-lint attr path";
        text = ''attrPath = "checks.crucible.phase1.gates.harnessLint";'';
      }
      {
        label = "phase1 gate:harness-lint import";
        text = "gate = import ./phase1-harness-lint.nix";
      }
    ];
    harnessFailures =
      lib.concatMap (
        required:
          lib.optionals (!(hasInfix (normalize required) harnessLintMainCode || hasInfix (normalize required) harnessLintScanCode)) [
            "crates/crucible-harness/tests/harness_lint.rs: missing T-DET-17 harness-lint evidence `${required}`"
          ]
      )
      requiredHarnessCode;
    denyCoverageFailures =
      lib.concatMap (
        required:
          lib.optionals (!(builtins.any (deny: deny.reason == required.reason && deny.rule == required.rule) denyPatterns)) [
            "tests/crucible/phase1-harness-lint.nix: missing deny-pattern coverage for `${required.rule}`"
          ]
      )
      requiredDenyCoverage;
    docFailures = [];
    baselineFailures = failuresFor "tests/crucible/harness-lint-baseline.txt" harnessLintBaseline [
      {
        label = "confinement baseline category";
        needle = "confinement\t";
      }
      {
        label = "error/logging baseline category";
        needle = "error-logging\t";
      }
      {
        label = "baseline count field";
        needle = "\tResult<_, String>\t\t32";
      }
    ];
    phaseWiringFailures =
      lib.concatMap (
        required:
          lib.optionals (!(hasInfix required.text defaultChecks)) [
            "tests/crucible/default.nix: ${required.label} wiring is missing"
          ]
      )
      requiredDefaultCheckBlocks;
  in
    harnessFailures ++ denyCoverageFailures ++ docFailures ++ baselineFailures ++ phaseWiringFailures;

  tAsrt17CompletionFailures =
    failuresFor "crates/crucible/tests/predicate_dsl.rs" predicateDsl [
      {
        label = "T-ASRT-17 regression module";
        needle = "Checks T-ASRT-17 predicate DSL desugaring.";
      }
      {
        label = "host predicate additivity evidence";
        needle = "uncovered predicates remain host-extensible";
      }
      {
        label = "unknown host predicate preserved";
        needle = "always(Predicate::named(\"custom-host\"))";
      }
      {
        label = "plan-aware property DSL coverage";
        needle = "Properties::from_assertions_for_world_and_plan";
      }
      {
        label = "plan-aware TOML DSL coverage";
        needle = "Properties::from_canonical_toml_for_world_and_plan";
      }
      {
        label = "trigger DSL coverage";
        needle = "Plan::from_event_graph_for_world";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" crucibleModel [
      {
        label = "TOML string DSL parsing";
        needle = "PredicateToml::Dsl(name)";
      }
      {
        label = "unknown named predicate additive preservation";
        needle = ".unwrap_or_else(|| predicate.clone())";
      }
      {
        label = "predicate DSL resolver";
        needle = "fn resolve_named_predicate_dsl_for_context(";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionProperties [
      {
        label = "harness-lint gate named for predicate DSL";
        needle = "`checks.crucible.phase1.gates.harnessLint`";
      }
    ];

  failures = sourceFailures ++ boundarySourceFailures ++ boundaryManifestFailures ++ productionSourceFailures ++ manifestFailures ++ clippyTierFailures ++ customStaticTierFailures ++ regressionFailures ++ spacedPathRegressionFailures ++ scrubRegressionFailures ++ errorLoggingRegressionFailures ++ manifestRegressionFailures ++ exceptionPolicyRegressionFailures ++ confinementRegressionFailures ++ tDet17CompletionFailures ++ tAsrt17CompletionFailures;
in
  if failures != []
  then throw "crucible phase1 harness-lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-harness-lint";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.crucible] ++ dependencies;

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            gate=gate:harness-lint
            tasks=T-ASRT-17,T-DET-17,T-HARN-2,T-HARN-27,T-HARN-28,T-CRATE-7,T-CRATE-8,T-STD-3,T-STD-4,T-STD-5,T-STD-6,T-DCE-7
            rust_test=crucible-harness::harness_lint
            reduction_path=crucible-sim,crucible-assert,crucible,crucible-protocol,crucible-device,crucible-session
            nondeterminism_confinement=crucible-daemon,crucible-cli,crucible-qemu:no-state-leak
            error_logging=typed-errors,no-production-unwrap,main-boundary-anyhow,no-library-stdout
            clippy_tier=checked-in-disallowed-list,workspace-deny-set,all-targets,hermetic-cargo-clippy
            custom_static_tier=rust-harness-lint-all-crucible-src,hash-iteration,default-random-hasher,unordered-select,immediate-safety-comments,distribution-metadata-flow
            reference_integrity=source-labels,checklist-state-needles,task-metadata-state
            nix_eval_source_scans=synthetic-regressions-and-wiring-only
            distribution_metadata_guardrail=reduce-decision-content-key-artifact-ban
            exception_policy=crucible-lint-allow-rationale,annotated-rust-allow,versioned-lint-surface
            predicate_dsl_host_closures=additive-unknown-named-predicates
            RESULT
          '';
        }
      ];
    }
