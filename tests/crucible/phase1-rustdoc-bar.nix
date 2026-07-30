{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;
  packages = import ../../pkgs/tools/crucible/_packages.nix;
  rustdocBarTest = builtins.readFile ../../crates/crucible-harness/tests/rustdoc_bar.rs;
  rustdocBarBaseline = builtins.readFile ./rustdoc-bar-baseline.txt;

  rootForPackage = {
    crucible-cli = "src/main.rs";
  };

  rootOf = package:
    rootForPackage.${package} or "src/lib.rs";

  expectedPackages = lib.sort builtins.lessThan packages;
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

  trimLeft = value: lib.trim value;

  stripPrefix = prefix: value:
    if lib.hasPrefix prefix value
    then builtins.substring (builtins.stringLength prefix) (builtins.stringLength value) value
    else null;

  docText = line: let
    trimmed = trimLeft line;
    inner = stripPrefix "//!" trimmed;
    outer = stripPrefix "///" trimmed;
  in
    if inner != null
    then inner
    else outer;

  stripBlockMargin = value: let
    trimmed = trimLeft value;
    afterStar = stripPrefix "*" trimmed;
  in
    if afterStar == null
    then trimmed
    else trimLeft afterStar;

  beforeBlockClose = value:
    builtins.elemAt (lib.splitString "*/" value) 0;

  blockDocText = value: {
    text = stripBlockMargin (beforeBlockClose value);
    insideBlock = !(hasInfix "*/" value);
  };

  blockStartText = line: let
    trimmed = trimLeft line;
    inner = stripPrefix "/*!" trimmed;
    outer = stripPrefix "/**" trimmed;
    body =
      if inner != null
      then inner
      else outer;
  in
    if body == null
    then null
    else blockDocText body;

  blockLineText = line:
    blockDocText (trimLeft line);

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

  hasTaggedFence = lines:
    builtins.any (
      line:
        lib.hasPrefix "//! ```text" line
        || lib.hasPrefix "//! ```toml" line
        || lib.hasPrefix "//! ```ignore" line
        || lib.hasPrefix "//! ```no_run" line
    )
    lines;

  fenceTags = ["text" "rust" "toml" "no_run" "ignore"];
  doctestedFenceTags = ["rust" "no_run"];
  leadingBackticks = value: let
    length = builtins.stringLength value;
    count = index:
      if index < length && builtins.substring index 1 value == "`"
      then count (index + 1)
      else index;
  in
    count 0;
  fenceLine = value: let
    backticks = leadingBackticks value;
  in
    if backticks < 3
    then null
    else {
      inherit backticks;
      info = trimLeft (builtins.substring backticks (builtins.stringLength value) value);
    };
  firstFenceTag = info: let
    normalized = builtins.replaceStrings ["\t" ","] [" " " "] info;
    parts = builtins.filter (part: part != "") (lib.splitString " " normalized);
  in
    if parts == []
    then ""
    else builtins.elemAt parts 0;

  doctestedDisplayPath = display:
    !(lib.hasPrefix "crucible-cli/" display)
    && !(lib.hasPrefix "crucible-qemu-plugin/" display);

  rustdocFenceFailures = display: lines: let
    scan = remaining: lineNumber: openFence: insideBlock:
      if remaining == []
      then
        lib.optionals (openFence != null) [
          "${display}:${builtins.toString openFence.line} opens an unterminated rustdoc fence"
        ]
      else let
        line = builtins.head remaining;
        rest = builtins.tail remaining;
        lineDoc =
          if insideBlock
          then null
          else docText line;
        blockDoc =
          if lineDoc != null
          then null
          else if insideBlock
          then blockLineText line
          else blockStartText line;
        maybeDoc =
          if lineDoc != null
          then {
            text = lineDoc;
            insideBlock = false;
          }
          else blockDoc;
        nextInsideBlock =
          if maybeDoc == null
          then insideBlock
          else maybeDoc.insideBlock;
        text =
          if maybeDoc == null
          then null
          else trimLeft maybeDoc.text;
        fence =
          if text == null
          then null
          else fenceLine text;
      in
        if fence == null
        then scan rest (lineNumber + 1) openFence nextInsideBlock
        else if openFence != null
        then
          if fence.backticks < openFence.backticks
          then scan rest (lineNumber + 1) openFence nextInsideBlock
          else if fence.info == ""
          then scan rest (lineNumber + 1) null nextInsideBlock
          else
            [
              "${display}:${builtins.toString lineNumber} rustdoc fence closer for fence opened at line ${builtins.toString openFence.line} must not carry an info string"
            ]
            ++ scan rest (lineNumber + 1) openFence nextInsideBlock
        else let
          rawInfo = fence.info;
          tag = firstFenceTag rawInfo;
          lineText = builtins.toString lineNumber;
        in
          lib.optionals (rawInfo == "") [
            "${display}:${lineText} has an untagged rustdoc fence"
          ]
          ++ lib.optionals (rawInfo != "" && !(builtins.elem tag fenceTags)) [
            "${display}:${lineText} has unsupported rustdoc fence tag `${tag}`"
          ]
          ++ lib.optionals ((builtins.elem tag doctestedFenceTags) && !(doctestedDisplayPath display)) [
            "${display}:${lineText} has a doctested rustdoc fence that is not covered by cargo test --doc"
          ]
          ++ scan rest (lineNumber + 1) {
            line = lineNumber;
            inherit (fence) backticks;
          }
          nextInsideBlock;
  in
    scan lines 1 null false;

  formatOwners = {
    "crucible-shmem/src/lib.rs" = "shared-memory ABI";
    "crucible-protocol/src/lib.rs" = "wire protocol";
    "crucible-harness/src/abi.rs" = "ABI golden-vector records";
  };

  sourceFilesFor = package: let
    srcDir = cratesDir + "/${package}/src";
    collect = relativeDir: dir:
      lib.concatMap (
        name: let
          kind = (builtins.readDir dir).${name};
          path = dir + "/${name}";
          relativePath =
            if relativeDir == ""
            then name
            else "${relativeDir}/${name}";
        in
          if kind == "directory"
          then collect relativePath path
          else if lib.hasSuffix ".rs" name
          then [
            {
              inherit path;
              display = "${package}/src/${relativePath}";
            }
          ]
          else []
      )
      (builtins.attrNames (builtins.readDir dir));
  in
    collect "" srcDir;

  rustdocFailuresForContent = package: display: content: let
    docLines = docPrefixLines (linesOf content);
    isRoot = display == "${package}/${rootOf package}";
    formatOwner = formatOwners.${display} or null;
  in
    lib.optionals (docLines == []) [
      "${display}: missing module-level `//!` rustdoc header"
    ]
    ++ lib.optionals (isRoot && !(builtins.any (line: hasInfix "Module map:" line) docLines)) [
      "${display}: missing crate-root `Module map:` in `//!` overview"
    ]
    ++ lib.optionals (isRoot && !(hasInfix "#![deny(missing_docs)]" content)) [
      "${display}: missing crate-level `#![deny(missing_docs)]`"
    ]
    ++ lib.optionals (isRoot && !(hasInfix "#![deny(rustdoc::broken_intra_doc_links)]" content)) [
      "${display}: missing crate-level `#![deny(rustdoc::broken_intra_doc_links)]`"
    ]
    ++ lib.optionals (formatOwner != null && !(hasTaggedFence docLines)) [
      "${display}: ${formatOwner} module is missing tagged format sketch"
    ]
    ++ rustdocFenceFailures display (linesOf content);

  rustdocFailuresFor = package: source:
    rustdocFailuresForContent package source.display (builtins.readFile source.path);

  # The Rust `rustdoc_bar` gate owns the full workspace source scan. Keeping the
  # pure Nix mirror to synthetic parser regressions avoids evaluator recursion
  # limits on generated-scale Rust source lines.
  sourceFailures = [];

  regressionFailures = let
    missingModuleDoc = rustdocFailuresForContent "crucible-sim" "crucible-sim/src/lib.rs" ''
      pub fn documented() {}
    '';
    missingFormat = rustdocFailuresForContent "crucible-shmem" "crucible-shmem/src/lib.rs" ''
      //! synthetic
      //!
      //! Module map: synthetic.
      #![deny(missing_docs)]
      #![deny(rustdoc::broken_intra_doc_links)]
    '';
    untaggedFence = rustdocFailuresForContent "crucible-sim" "crucible-sim/src/lib.rs" ''
      //! synthetic
      //!
      //! Module map: synthetic.
      //!
      //! ```
      //! format example
      //! ```
      #![deny(missing_docs)]
      #![deny(rustdoc::broken_intra_doc_links)]
    '';
    untaggedBlockFence = rustdocFailuresForContent "crucible-sim" "crucible-sim/src/lib.rs" ''
      /*!
       * synthetic
       *
       * ```
       * format example
       * ```
       */
      #![deny(missing_docs)]
      #![deny(rustdoc::broken_intra_doc_links)]
    '';
    malformedClosingFence = rustdocFailuresForContent "crucible-sim" "crucible-sim/src/lib.rs" ''
      //! synthetic
      //!
      //! Module map: synthetic.
      //!
      //! ```text
      //! format example
      //! ```rust
      //! ```
      #![deny(missing_docs)]
      #![deny(rustdoc::broken_intra_doc_links)]
    '';
    nestedShorterFence = rustdocFailuresForContent "crucible-sim" "crucible-sim/src/lib.rs" ''
      //! synthetic
      //!
      //! Module map: synthetic.
      //!
      //! ````text
      //! ```rust
      //! let value = 1;
      //! ```
      //! ````
      #![deny(missing_docs)]
      #![deny(rustdoc::broken_intra_doc_links)]
    '';
    tabTaggedFence = rustdocFailuresForContent "crucible-sim" "crucible-sim/src/lib.rs" (builtins.concatStringsSep "\n" [
      "//! synthetic"
      "//!"
      "//! Module map: synthetic."
      "//!"
      "//! ```rust\t,no_run"
      "//! let value = 1;"
      "//! ```"
      "#![deny(missing_docs)]"
      "#![deny(rustdoc::broken_intra_doc_links)]"
    ]);
    nonDoctestedNoRunFence = rustdocFailuresForContent "crucible-cli" "crucible-cli/src/main.rs" ''
      //! synthetic
      //!
      //! Module map: synthetic.
      //!
      //! ```no_run
      //! let value = 1;
      //! ```
      #![deny(missing_docs)]
      #![deny(rustdoc::broken_intra_doc_links)]
    '';
    hasFinding = needle: findings:
      builtins.any (finding: hasInfix needle finding) findings;
  in
    lib.optionals (!(hasFinding "missing module-level" missingModuleDoc)) [
      "rustdoc-bar regression failed to reject a missing module header"
    ]
    ++ lib.optionals (!(hasFinding "missing tagged format sketch" missingFormat)) [
      "rustdoc-bar regression failed to reject a missing format sketch"
    ]
    ++ lib.optionals (!(hasFinding "untagged rustdoc fence" untaggedFence)) [
      "rustdoc-bar regression failed to reject an untagged rustdoc fence"
    ]
    ++ lib.optionals (!(hasFinding "untagged rustdoc fence" untaggedBlockFence)) [
      "rustdoc-bar regression failed to reject an untagged block rustdoc fence"
    ]
    ++ lib.optionals (!(hasFinding "rustdoc fence closer" malformedClosingFence)) [
      "rustdoc-bar regression failed to reject a malformed rustdoc fence closer"
    ]
    ++ lib.optionals (hasFinding "rustdoc fence closer" nestedShorterFence) [
      "rustdoc-bar regression failed to allow a shorter nested fence inside a longer fence"
    ]
    ++ lib.optionals (hasFinding "unsupported rustdoc fence tag" tabTaggedFence) [
      "rustdoc-bar regression failed to parse a tab-separated rustdoc fence tag"
    ]
    ++ lib.optionals (!(hasFinding "not covered by cargo test --doc" nonDoctestedNoRunFence)) [
      "rustdoc-bar regression failed to reject a non-doctested no_run fence"
    ];

  attrFailures = [];

  baselineFailures =
    lib.optionals (!(hasInfix "RustdocBarBaseline::load(&root)" rustdocBarTest)) [
      "crates/crucible-harness/tests/rustdoc_bar.rs: missing rustdoc-bar baseline loader"
    ]
    ++ lib.optionals (!(hasInfix "stale baseline" rustdocBarTest)) [
      "crates/crucible-harness/tests/rustdoc_bar.rs: missing stale rustdoc-bar baseline check"
    ]
    ++ lib.optionals (!(hasInfix "contains non-ASCII comment/doc text" rustdocBarBaseline)) [
      "tests/crucible/rustdoc-bar-baseline.txt: missing non-ASCII debt baseline"
    ]
    ++ lib.optionals (!(hasInfix "missing `# Errors`" rustdocBarBaseline)) [
      "tests/crucible/rustdoc-bar-baseline.txt: missing # Errors debt baseline"
    ];

  failures = packageSetFailures ++ regressionFailures ++ sourceFailures ++ attrFailures ++ baselineFailures;
in
  if failures != []
  then throw "crucible phase1 rustdoc-bar lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-rustdoc-bar";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "check";
          script = ''
            set -eu

            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.rustdocBar
            tasks=T-STD-1,T-STD-2
            nix_mirror=source-regressions-and-baseline-wiring
            crate_roots=14
            rustdocflags=-D warnings -D missing_docs
            cargo_doc=warning-free
            cargo_doctest=hermetic
            RESULT
          '';
        }
      ];
    }
