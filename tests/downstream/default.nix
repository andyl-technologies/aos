##! Checks for the downstream flake API.
##!
##! `api-docs` keeps docs/engineering/downstream/flake-api.md and the exported
##! `lib.<system>` set in agreement. It reads the three marked tables in that
##! document: exported names, package attributes, and removed names. Every
##! row inside the markers must have the documented fixed format.
##!
##! The fixture is a downstream flake whose `outputs` function receives a
##! flake-shaped `aos` input. Its `legacyPackages` contains only the package
##! attributes the contract documents, so a fixture that reaches for any other
##! package fails evaluation. `fixture-eval` instantiates every output without
##! building; `fixture` builds the packages and runs the fixture's checks.
##!
##! `toolchain-release` keeps the toolchain set in the release package matrix
##! on both Linux platforms, and `toolchain-cache-check` exercises the
##! downstream cache command against recorded Nix output. `flake-outputs`
##! instantiates every per-system flake output of the cross-built systems.
{
  pkgs,
  lib,
  system,
  # Flake-shaped AOS exports: `lib.<system>` and `legacyPackages.<system>`.
  aos,
  # The repository flake's outputs, or null to skip `flake-outputs`.
  flakeOutputs ? null,
}: let
  contractPath = ../../docs/engineering/downstream/flake-api.md;
  contractLines = lib.splitString "\n" (builtins.readFile contractPath);

  exported = aos.lib.${system};
  packageSet = aos.legacyPackages.${system};

  # --- Contract tables ---

  # Rows between `<!-- downstream-api:<table>:begin -->` and its end marker,
  # without the header and separator rows.
  tableRows = table: let
    begin = "<!-- downstream-api:${table}:begin -->";
    end = "<!-- downstream-api:${table}:end -->";
    step = state: line:
      if line == begin
      then state // {inside = true;}
      else if line == end
      then state // {inside = false;}
      else if state.inside
      then state // {rows = state.rows ++ [line];}
      else state;
    collected = builtins.foldl' step {
      inside = false;
      rows = [];
    } (builtins.filter (line: line != "") contractLines);
    isHeader = row: lib.hasPrefix "| Name |" row || lib.hasPrefix "| --- |" row;
  in
    if builtins.length (builtins.filter (line: line == begin) contractLines) != 1
    then throw "${toString contractPath}: expected exactly one '${begin}' marker"
    else builtins.filter (row: !isHeader row) collected.rows;

  # Parses each row with `pattern`, whose first group is the name. Rows that
  # do not match are reported instead of being skipped.
  parseTable = table: pattern: let
    rows = tableRows table;
    parsed =
      map (row: {
        inherit row;
        fields = builtins.match pattern row;
      })
      rows;
  in {
    entries = map (entry: entry.fields) (builtins.filter (entry: entry.fields != null) parsed);
    malformed = map (entry: "${table}: ${entry.row}") (builtins.filter (entry: entry.fields == null) parsed);
  };

  namePattern = "`([A-Za-z][A-Za-z0-9_']*([.][A-Za-z][A-Za-z0-9_'-]*)?)`";
  versionPattern = "([0-9]+[.][0-9]+)";

  exportsTable = parseTable "exports" "[|] ${namePattern} [|] (function|namespace|value) [|] ${versionPattern} [|] (stable|deprecated) [|] [^|]+ [|]";
  packagesTable = parseTable "packages" "[|] `([A-Za-z0-9][A-Za-z0-9_+.-]*)` [|] ${versionPattern} [|] [^|]+ [|]";
  removedTable = parseTable "removed" "[|] ${namePattern} [|] ${versionPattern} [|] [^|]+ [|]";

  documentedKinds = builtins.listToAttrs (map (fields: {
      name = builtins.elemAt fields 0;
      value = builtins.elemAt fields 2;
    })
    exportsTable.entries);
  documentedNames = builtins.attrNames documentedKinds;
  documentedRows = map builtins.head exportsTable.entries;
  documentedPackages = map builtins.head packagesTable.entries;
  removedNames = map builtins.head removedTable.entries;

  documentedVersion = let
    matches = builtins.filter (fields: fields != null) (
      map (builtins.match "[*][*]API version:[*][*] ${versionPattern}") contractLines
    );
  in
    if builtins.length matches == 1
    then builtins.head (builtins.head matches)
    else null;

  # --- Exported names ---

  kindOf = value:
    if builtins.isFunction value || (builtins.isAttrs value && value ? __functor)
    then "function"
    else if builtins.isAttrs value && !(lib.isDerivation value)
    then "namespace"
    else "value";

  # Namespaces contribute their own name and one dotted name per member.
  exportedKinds = builtins.listToAttrs (builtins.concatMap (
    name: let
      value = exported.${name};
      kind = kindOf value;
    in
      [
        {
          inherit name;
          value = kind;
        }
      ]
      ++ lib.optionals (kind == "namespace") (map (member: {
        name = "${name}.${member}";
        value = kindOf value.${member};
      }) (builtins.attrNames value))
  ) (builtins.attrNames exported));
  exportedNames = builtins.attrNames exportedKinds;

  # --- Findings ---

  undocumented = builtins.filter (name: !(documentedKinds ? ${name})) exportedNames;
  disappeared = builtins.filter (name: !(exportedKinds ? ${name})) documentedNames;
  wrongKind =
    builtins.filter (
      name: exportedKinds ? ${name} && exportedKinds.${name} != documentedKinds.${name}
    )
    documentedNames;
  stillExported = builtins.filter (name: exportedKinds ? ${name}) removedNames;
  missingPackages = builtins.filter (name: !(packageSet ? ${name})) documentedPackages;
  duplicateNames = lib.unique (builtins.filter (
      name: builtins.length (builtins.filter (row: row == name) documentedRows) > 1
    )
    documentedRows);

  section = title: items:
    lib.optional (items != []) "${title}:\n${lib.concatMapStrings (item: "  ${item}\n") items}";

  findings =
    section "Malformed rows" (exportsTable.malformed ++ packagesTable.malformed ++ removedTable.malformed)
    ++ section "Exported but not documented" undocumented
    ++ section "Documented but no longer exported" disappeared
    ++ section "Documented kind differs from the export" (map (name: "${name}: documented ${documentedKinds.${name}}, exported ${exportedKinds.${name}}") wrongKind)
    ++ section "Removed names that are still exported" stillExported
    ++ section "Documented package attributes missing from legacyPackages" missingPackages
    ++ lib.optional (duplicateNames != []) "Names documented more than once: ${toString duplicateNames}\n"
    ++ lib.optional (documentedVersion != exported.apiVersion or null)
    "API version: the contract states ${toString documentedVersion}, lib.apiVersion is ${toString (exported.apiVersion or null)}\n";

  report = lib.concatStrings findings;

  # --- Fixture ---

  # The fixture sees the builder API unchanged and only the documented
  # package attributes, mirroring what the contract promises.
  contractAos = {
    lib.${system} = exported;
    legacyPackages.${system} = builtins.listToAttrs (map (name: {
        inherit name;
        value = packageSet.${name};
      })
      (builtins.filter (name: packageSet ? ${name}) documentedPackages));
  };

  fixtureFlake = import ./fixture/flake.nix;
  fixtureOutputs = fixtureFlake.outputs {
    self = fixtureOutputs // {outPath = ./fixture;};
    aos = contractAos;
  };
  fixturePackages = builtins.attrValues fixtureOutputs.packages.${system};
  fixtureChecks = builtins.attrValues fixtureOutputs.checks.${system};
  fixtureShells = builtins.attrValues fixtureOutputs.devShells.${system};

  passingCheck = pname: extra:
    pkgs.mkDerivation ({
        inherit pname;
        version = "0";
        src = null;
        phases = [
          {
            name = "check";
            script = ''
              mkdir -p "$out"
              echo PASS > "$out/result"
            '';
          }
        ];
      }
      // extra);
in
  {
    api-docs = pkgs.mkDerivation {
      pname = "aos-downstream-api-docs-check";
      version = "0";
      src = null;
      inherit report;
      passAsFile = ["report"];
      phases = [
        {
          name = "check";
          script = ''
            if [ -s "$reportPath" ]; then
              echo "docs/engineering/downstream/flake-api.md does not match lib.${system}:" >&2
              cat "$reportPath" >&2
              exit 1
            fi
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
    };

    # Discarding the output dependency keeps each `.drv` file as an input
    # without realizing its outputs, so this check stays evaluation-only.
    fixture-eval = passingCheck "aos-downstream-fixture-eval-check" {
      fixtureDerivations = map (drv: builtins.unsafeDiscardOutputDependency drv.drvPath) (
        fixturePackages ++ fixtureChecks ++ fixtureShells
      );
    };

    toolchain-release = import ./toolchain-release.nix {inherit pkgs lib;};
    toolchain-cache-check = import ./toolchain-cache-check.nix {inherit pkgs;};

    # The outputs are string inputs rather than build dependencies: nothing
    # here executes them, and cross-built outputs cannot run on the builder.
    fixture = passingCheck "aos-downstream-fixture-check" {
      fixtureResults = map toString (fixturePackages ++ fixtureChecks);
    };
  }
  // lib.optionalAttrs (flakeOutputs != null) {
    flake-outputs = import ./flake-outputs.nix {
      inherit pkgs lib flakeOutputs;
    };
  }
