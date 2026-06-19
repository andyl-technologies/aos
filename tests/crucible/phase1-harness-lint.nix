{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase0.gates.harnessLint",
}: let
  allPackages = import ../../pkgs/tools/crucible/_packages.nix;
  workspaceManifest = builtins.readFile ../../crates/Cargo.toml;
  clippyConfig = builtins.readFile ../../crates/clippy.toml;
  harnessLintRust = builtins.readFile ../../crates/crucible-harness/tests/harness_lint.rs;
  cruciblePackageNix = builtins.readFile ../../pkgs/tools/crucible/crucible.nix;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (i: i) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

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
    final = builtins.foldl' step {
      mode = "code";
      depth = 0;
      skip = 0;
      out = "";
    } chars;
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
  binaryPackages = ["crucible-cli"];
  libraryPackages = builtins.filter (package: !(builtins.elem package binaryPackages)) allPackages;
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
    } indexes;

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

  isBinaryBoundarySource = package: path:
    package == "crucible-cli" && toString path == toString (../../crates + "/crucible-cli/src/main.rs");

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
    ] label manifest
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

  normalize = builtins.replaceStrings [" " "\t" "\n" "\r"] ["" "" "" ""];

  sourceFiles =
    lib.concatMap (
      package:
        listRustFiles (../../crates + "/${package}/src")
    )
    reductionPackages;

  sourceFailures =
    lib.concatMap (
      path:
        scanContent (toString path) (builtins.readFile path)
    )
    sourceFiles;

  productionSourceFailures =
    lib.concatMap (
      package:
        lib.concatMap (
          path:
            scanErrorLoggingContent
            (toString path)
            (isBinaryBoundarySource package path)
            (builtins.readFile path)
        )
        (listRustFiles (../../crates + "/${package}/src"))
    )
    allPackages;

  manifestFailures =
    lib.concatMap (
      package:
        manifestErrorPolicyFailures package
    )
    libraryPackages;

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
        "packageFlags"
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
      "unordered_select_failures"
      "select_macro_is_unordered"
      "bare_unsafe_block_failures"
      "has_immediately_preceding_safety_comment"
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
      lib.optionals (!(hasInfix "doCheck=true" (normalize cruciblePackageNix) && hasInfix "cargoTestFlags=packageFlags" (normalize cruciblePackageNix))) [
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
        tokio::select! { _ = async {} => {} }
      }
    '';
  in
    if builtins.length findings >= 4
    then []
    else [
      "harness-lint regression expected wall-clock, RNG, unordered-map, and select findings"
    ];

  spacedPathRegressionFailures = let
    findings = scanContent "spaced-regression.rs" ''
      use std::collections::{HashMap, HashSet};
      use std::time::{Instant, SystemTime};

      fn bad() {
        let _ = HashMap :: <u8, u8> :: new();
        let _ = HashSet :: <u8> :: new();
        let _ = SystemTime :: now();
        let _ = Instant :: now();
        rand :: thread_rng();
        rand :: rng();
        tokio::select ! { _ = async {} => {} }
      }
    '';
  in
    if builtins.length findings >= 5
    then []
    else [
      "harness-lint regression failed to reject spaced paths and grouped imports"
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
    cliModuleFindings = scanErrorLoggingContent "crucible-cli/src/command.rs" false ''
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
    ++ lib.optionals (builtins.length cliModuleFindings < 2) [
      "harness-lint regression failed to reject CLI module boundary drift"
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
    handRolledFindings = scanManifestErrorPolicyContent "crucible-harness/Cargo.toml" ''
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
    stringlyUnannotatedFindings = scanErrorLoggingContent "stringly-unannotated.rs" false ''
      fn bad() {
        let _value: Result<(), String> = Ok(());
      }
    '';
  in
    if allowedFindings == [] && unannotatedFindings != [] && malformedFindings != [] && malformedSyntaxFindings != [] && wrongRuleFindings != [] && multilineFindings != [] && stringlyAllowedFindings == [] && stringlyUnannotatedFindings != []
    then []
    else [
      "harness-lint regression failed to enforce annotated exception policy"
    ];

  failures = sourceFailures ++ productionSourceFailures ++ manifestFailures ++ clippyTierFailures ++ customStaticTierFailures ++ regressionFailures ++ spacedPathRegressionFailures ++ scrubRegressionFailures ++ errorLoggingRegressionFailures ++ manifestRegressionFailures ++ exceptionPolicyRegressionFailures;
in
  if failures != []
  then throw "crucible phase1 harness-lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-harness-lint";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.crucible];

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
            tasks=T-CRATE-7,T-STD-3,T-STD-4,T-STD-5,T-STD-6
            rust_test=crucible-harness::harness_lint
            reduction_path=crucible-sim,crucible-assert,crucible,crucible-protocol,crucible-device,crucible-session
            error_logging=typed-errors,no-production-unwrap,main-boundary-anyhow,no-library-stdout
            clippy_tier=checked-in-disallowed-list,workspace-deny-set,all-targets,hermetic-cargo-clippy
            custom_static_tier=rust-harness-lint-all-crucible-src,hash-iteration,unordered-select,immediate-safety-comments
            exception_policy=crucible-lint-allow-rationale,annotated-rust-allow,versioned-lint-surface
            RESULT
          '';
        }
      ];
    }
