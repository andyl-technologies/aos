{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase0.gates.harnessLint",
}: let
  allPackages = import ../../pkgs/tools/crucible/_packages.nix;

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

  denyPatterns = [
    {
      pattern = "std::time::SystemTime";
      reason = "host wall-clock";
    }
    {
      pattern = "SystemTime::now";
      reason = "host wall-clock";
    }
    {
      pattern = "std::time::Instant";
      reason = "host monotonic time";
    }
    {
      pattern = "Instant::now";
      reason = "host monotonic time";
    }
    {
      pattern = "rand::thread_rng";
      reason = "thread/global RNG";
    }
    {
      pattern = "thread_rng(";
      reason = "thread/global RNG";
    }
    {
      pattern = "rand::rng(";
      reason = "thread/global RNG";
    }
    {
      pattern = "StdRng::from_entropy";
      reason = "thread/global RNG";
    }
    {
      pattern = "SmallRng::from_entropy";
      reason = "thread/global RNG";
    }
    {
      pattern = "OsRng";
      reason = "host RNG";
    }
    {
      pattern = "getrandom";
      reason = "host RNG";
    }
    {
      pattern = "std::collections::HashMap";
      reason = "unordered map/set";
    }
    {
      pattern = "std::collections::HashSet";
      reason = "unordered map/set";
    }
    {
      pattern = "HashMap<";
      reason = "unordered map/set";
    }
    {
      pattern = "HashSet<";
      reason = "unordered map/set";
    }
    {
      pattern = "HashMap::";
      reason = "unordered map/set";
    }
    {
      pattern = "HashSet::";
      reason = "unordered map/set";
    }
    {
      pattern = "tokio::select!";
      reason = "nondeterministic select";
    }
    {
      pattern = "futures::select!";
      reason = "nondeterministic select";
    }
    {
      pattern = "select!";
      reason = "nondeterministic select";
    }
  ];

  productionDenyPatterns = [
    {
      pattern = ".unwrap(";
      reason = "panic shortcut";
    }
    {
      pattern = ".expect(";
      reason = "panic shortcut";
    }
  ];

  libraryDenyPatterns = [
    {
      pattern = "println!(";
      reason = "direct stdout/stderr diagnostic";
    }
    {
      pattern = "eprintln!(";
      reason = "direct stdout/stderr diagnostic";
    }
    {
      pattern = "print!(";
      reason = "direct stdout/stderr diagnostic";
    }
    {
      pattern = "anyhow";
      reason = "erased error";
    }
    {
      pattern = "eyre";
      reason = "erased error";
    }
    {
      pattern = "miette";
      reason = "erased error";
    }
    {
      pattern = "bail!(";
      reason = "erased error";
    }
    {
      pattern = "dynError";
      reason = "erased error";
    }
    {
      pattern = "dynstd::error::Error";
      reason = "erased error";
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

  scanDenyPatterns = patterns: label: content:
    scanNormalizedDenyPatterns patterns label (normalize (scrubRustContent content));

  scanManifestDenyPatterns = patterns: label: content:
    scanNormalizedDenyPatterns patterns label (normalize content);

  scanContent = scanDenyPatterns denyPatterns;

  scanProductionContent = label: content:
    scanDenyPatterns productionDenyPatterns label content;

  scanLibraryContent = label: normalizedContent:
    scanNormalizedDenyPatterns libraryDenyPatterns label normalizedContent
    ++ lib.optionals (hasInfix "Result<" normalizedContent && hasInfix ",String>" normalizedContent) [
      "${label}: banned stringly error pattern `Result<_, String>`"
    ];

  scanErrorLoggingContent = label: isBinaryBoundary: content: let
    normalizedContent = normalize (scrubRustContent content);
  in
    scanNormalizedDenyPatterns productionDenyPatterns label normalizedContent
    ++ lib.optionals (!isBinaryBoundary) (scanLibraryContent label normalizedContent);

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

  failures = sourceFailures ++ productionSourceFailures ++ manifestFailures ++ regressionFailures ++ spacedPathRegressionFailures ++ scrubRegressionFailures ++ errorLoggingRegressionFailures ++ manifestRegressionFailures;
in
  if failures != []
  then throw "crucible phase1 harness-lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-harness-lint";
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
            gate=gate:harness-lint
            tasks=T-CRATE-7,T-STD-3
            rust_test=crucible-harness::harness_lint
            reduction_path=crucible-sim,crucible-assert,crucible,crucible-protocol,crucible-device,crucible-session
            error_logging=typed-errors,no-production-unwrap,main-boundary-anyhow,no-library-stdout
            RESULT
          '';
        }
      ];
    }
