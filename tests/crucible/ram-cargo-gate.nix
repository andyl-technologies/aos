# Runs exact Rust cases for format/model evidence. This runner deliberately has
# no live or packaged evidence mode: passing a model cannot qualify a VM pager.
{
  pkgs,
  lib,
  attrPath,
  gateName,
  evidenceClass,
  testGroups,
  requirementIds,
}: let
  indexedMap = function: values:
    builtins.genList (index: function index (builtins.elemAt values index)) (builtins.length values);

  validEvidenceClass = builtins.elem evidenceClass ["format" "model"];
  cases = lib.concatMap (group: group.cases) testGroups;
  caseKeys =
    lib.concatMap (
      group:
        map (case: "${group.package}::${group.target}::${case.name}") group.cases
    )
    testGroups;
  validRoles = builtins.all (case: builtins.elem case.role ["positive" "adversarial"]) cases;
  hasRole = role: builtins.any (case: case.role == role) cases;
  validNames = builtins.all (
    value: builtins.isString value && builtins.match "[a-zA-Z0-9_:-]+" value != null
  ) (caseKeys ++ requirementIds ++ [gateName]);
  validGroups =
    builtins.all (
      group:
        group.cases
        != []
        && builtins.isString group.package
        && builtins.match "[a-zA-Z0-9_-]+" group.package != null
        && builtins.isString group.target
        && builtins.match "[a-zA-Z0-9_-]+" group.target != null
    )
    testGroups;

  src = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib src;};
  inventory = builtins.toJSON {
    schema = "crucible.ram-cargo-evidence.v1";
    inherit attrPath gateName evidenceClass requirementIds testGroups;
    advertisedCapabilities = [];
  };

  runGroup = index: group: let
    features = group.features or [];
    selection =
      if group.target == "lib"
      then ["--lib"]
      else ["--test" group.target];
    arguments =
      [
        "--frozen"
        "--offline"
        "--manifest-path"
        "crates/Cargo.toml"
        "--package"
        group.package
      ]
      ++ selection
      ++ lib.optionals (features != []) ["--features" (builtins.concatStringsSep "," features)];
    cargoArguments = lib.escapeShellArgs arguments;
    logPrefix = "group-${toString index}";
    runCase = caseIndex: case: ''
      test "$(grep -Fxc ${lib.escapeShellArg "${case.name}: test"} "$out/evidence/${logPrefix}.list")" -eq 1
      cargo test ${cargoArguments} --target-dir "$TMPDIR/ram-cargo-target" \
        -- ${lib.escapeShellArg case.name} --exact --test-threads=1 \
        > "$out/evidence/${logPrefix}-case-${toString caseIndex}.log" 2>&1
      cat "$out/evidence/${logPrefix}-case-${toString caseIndex}.log"
      grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' \
        "$out/evidence/${logPrefix}-case-${toString caseIndex}.log"
    '';
  in ''
    cargo test ${cargoArguments} --target-dir "$TMPDIR/ram-cargo-target" \
      -- --list > "$out/evidence/${logPrefix}.list" 2>&1
    ${lib.concatStringsSep "\n" (indexedMap runCase group.cases)}
  '';
in
  if !validEvidenceClass
  then throw "RAM Cargo gates accept format/model evidence only; live pager qualification needs a deployed VM gate"
  else if testGroups == [] || requirementIds == [] || !validGroups || !validNames
  then throw "RAM Cargo gates require bounded named cases and normative requirement bindings"
  else if !validRoles || !hasRole "positive" || !hasRole "adversarial"
  then throw "RAM Cargo gates require both real positive and adversarial cases"
  else if builtins.length (lib.unique caseKeys) != builtins.length caseKeys
  then throw "RAM Cargo gate case bindings must be unique"
  else
    pkgs.mkDerivation {
      pname = builtins.replaceStrings [":" "."] ["-" "-"] "crucible-${gateName}";
      version = "0";
      inherit src;
      buildDeps = [pkgs.coreutils pkgs.grep pkgs.sed pkgs.rust pkgs.pkg-config pkgs.sqlite];
      runtimeDeps = [pkgs.sqlite];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
            export RUSTFLAGS="-C link-arg=-Wl,-rpath,${pkgs.sqlite}/lib"
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          '';
        }
        {
          name = "run-exact-cases";
          script = ''
            set -eu
            mkdir -p "$out/evidence"
            ${lib.concatStringsSep "\n" (indexedMap runGroup testGroups)}
          '';
        }
        {
          name = "write-evidence";
          script = ''
            set -eu
            printf '%s\n' ${lib.escapeShellArg inventory} > "$out/evidence/inventory.json"
            {
              printf 'PASS\n'
              printf 'check=%s\n' ${lib.escapeShellArg attrPath}
              printf 'gate_candidate=%s\n' ${lib.escapeShellArg gateName}
              printf 'evidence_class=%s\n' ${lib.escapeShellArg evidenceClass}
              printf 'qualification=component-only\n'
              printf 'advertised_capabilities=\n'
              printf 'case_count=%s\n' ${lib.escapeShellArg (toString (builtins.length cases))}
              printf 'requirements=%s\n' ${lib.escapeShellArg (builtins.concatStringsSep "," requirementIds)}
            } > "$out/result"
          '';
        }
      ];
    }
