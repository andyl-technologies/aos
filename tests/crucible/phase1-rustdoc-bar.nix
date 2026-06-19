{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;
  packages = import ../../pkgs/tools/crucible/_packages.nix;

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

  hasTaggedFence = lines:
    builtins.any (
      line:
        lib.hasPrefix "//! ```text" line
        || lib.hasPrefix "//! ```toml" line
        || lib.hasPrefix "//! ```ignore" line
        || lib.hasPrefix "//! ```no_run" line
    )
    lines;

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
    ];

  rustdocFailuresFor = package: source:
    rustdocFailuresForContent package source.display (builtins.readFile source.path);

  sourceFailures =
    lib.concatMap (
      package:
        lib.concatMap (source: rustdocFailuresFor package source) (sourceFilesFor package)
    )
    packages;

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
    hasFinding = needle: findings:
      builtins.any (finding: hasInfix needle finding) findings;
  in
    lib.optionals (!(hasFinding "missing module-level" missingModuleDoc)) [
      "rustdoc-bar regression failed to reject a missing module header"
    ]
    ++ lib.optionals (!(hasFinding "missing tagged format sketch" missingFormat)) [
      "rustdoc-bar regression failed to reject a missing format sketch"
    ];

  attrFailures =
    lib.optionals (!(builtins.hasAttr "crucible" pkgs)) [
      "pkgs.crucible is not exposed by the AOS package set"
    ];

  packagesToCheck =
    if attrFailures == []
    then {
      inherit (pkgs) crucible;
    }
    else {};

  failures = packageSetFailures ++ regressionFailures ++ sourceFailures ++ attrFailures;
in
  if failures != []
  then throw "crucible phase1 rustdoc-bar lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-rustdoc-bar";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        packagesToCheck.crucible
      ];

      phases = [
        {
          name = "check";
          script = ''
            set -eu

            test -f ${packagesToCheck.crucible}/nix-support/crucible-build-info
            grep -q '^cargo_doc=warning-free$' \
              ${packagesToCheck.crucible}/nix-support/crucible-build-info
            grep -q '^rustdocflags=-D warnings -D missing_docs$' \
              ${packagesToCheck.crucible}/nix-support/crucible-build-info

            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.rustdocBar
            tasks=T-STD-1
            crate_roots=14
            rustdocflags=-D warnings -D missing_docs
            cargo_doc=warning-free
            RESULT
          '';
        }
      ];
    }
