{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase0.gates.harnessLint",
}: let
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

  reductionPackages = [
    "crucible-sim"
    "crucible-assert"
    "crucible"
    "crucible-protocol"
    "crucible-device"
    "crucible-session"
  ];

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

  scanContent = label: content:
    let
      normalizedContent = normalize content;
    in
      lib.concatMap (
        deny:
          if hasInfix (normalize deny.pattern) normalizedContent
          then [
            "${label}: banned ${deny.reason} pattern `${deny.pattern}`"
          ]
          else []
      )
      denyPatterns;

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

  failures = sourceFailures ++ regressionFailures ++ spacedPathRegressionFailures;
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
            tasks=T-CRATE-7
            rust_test=crucible-harness::harness_lint
            reduction_path=crucible-sim,crucible-assert,crucible,crucible-protocol,crucible-device,crucible-session
            RESULT
          '';
        }
      ];
    }
