##! lib/testing/ability-authoring-conformance.nix - Shared corpus Nix checks.
{
  pkgs,
  lib,
}: let
  corpus = builtins.fromJSON (builtins.readFile ../../tests/abilities/conformance/v1.json);
  runner = import ../../tests/abilities/conformance/runner.nix {
    inherit (lib) abilities;
  };

  unique = values:
    builtins.length values
    == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (value: {
        name = value;
        value = true;
      })
      values)));

  uniqueValues = values:
    builtins.attrNames (builtins.listToAttrs (builtins.map (value: {
        name = value;
        value = true;
      })
      values));

  recipeIsBounded = case: let
    arguments = case.arguments;
    depth = arguments.depth or 0;
    items = arguments.items or arguments.count or arguments.chunks or 0;
    generatedBytes =
      if arguments ? chunk_bytes && arguments ? count
      then arguments.chunk_bytes * arguments.count
      else 0;
  in
    depth
    <= corpus.recipe_limits.max_generated_depth
    && items <= corpus.recipe_limits.max_generated_items
    && generatedBytes <= corpus.recipe_limits.max_generated_string_bytes;

  checkAcceptedCase = case: let
    evaluated = builtins.tryEval (builtins.deepSeq (runner.evaluate case) (runner.evaluate case));
  in
    if case.expected.outcome == "accept"
    then evaluated.success && evaluated.value == case.expected.value
    else true;

  coverageFor = consumer: namespace:
    uniqueValues (builtins.concatLists (builtins.map (
        case: (runner.coverage case).${namespace}
      )
      (builtins.filter (case: builtins.elem consumer case.consumers) corpus.cases)));

  nixCases = builtins.filter (case: builtins.elem "nix" case.consumers) corpus.cases;
  caseIds = builtins.map (case: case.id) corpus.cases;
  coverageCases =
    builtins.filter (
      case:
        builtins.any (namespace: (runner.coverage case).${namespace} != []) [
          "abilities"
          "effects"
          "schemas"
        ]
    )
    corpus.cases;
  directFixture = pkgs.mkDerivation {
    pname = "aos-ability-authoring-direct-fixture";
    version = "1";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib"
          cp -R ${../.}/. "$out/lib/"
          cp ${../../tests/abilities/conformance/direct.nix} "$out/direct.nix"
          cp ${../../tests/abilities/conformance/runner.nix} "$out/runner.nix"
          cp ${../../tests/abilities/composition.nix} "$out/composition.nix"
          cp ${../../tests/abilities/effects.nix} "$out/effects.nix"
        '';
      }
    ];
  };
in
  assert corpus.schema == "aos.ability.authoring-conformance/v1";
  assert corpus.recipe_limits
  == {
    max_generated_depth = 64;
    max_generated_items = 2000000;
    max_generated_string_bytes = 34603008;
  };
  assert unique caseIds;
  assert builtins.all (case: case.consumers != [] && unique case.consumers) corpus.cases;
  assert builtins.all recipeIsBounded corpus.cases;
  # Any public helper addition must extend the checked-in corpus inventory.
  assert corpus.public_helpers.abilities == builtins.attrNames lib.abilities;
  assert corpus.public_helpers.schemas == builtins.attrNames lib.abilities.schemas;
  assert corpus.public_helpers.effects == builtins.attrNames lib.abilities.effects;
  assert builtins.attrNames lib.abilities.declarationModule.options
  == ["abilities" "abilityBindings"];
  assert builtins.all checkAcceptedCase nixCases;
  assert builtins.all (
    case: builtins.all (consumer: builtins.elem consumer case.consumers) ["nix" "evaluator"]
  )
  coverageCases;
  assert builtins.all (
    consumer:
      builtins.all (
        namespace: coverageFor consumer namespace == corpus.public_helpers.${namespace}
      ) ["abilities" "effects" "schemas"]
  ) ["nix" "evaluator"];
    pkgs.mkDerivation {
      pname = "aos-ability-authoring-conformance-v1";
      version = "0";
      src = null;
      buildDeps = [pkgs.jq pkgs.nix pkgs.grep];
      phases = [
        {
          name = "check";
          script = ''
            export HOME="$TMPDIR/home"
            export NIX_STATE_DIR="$TMPDIR/nix-state"
            export NIX_CONF_DIR="$TMPDIR/nix-conf"
            mkdir -p "$HOME" "$NIX_STATE_DIR/profiles" "$NIX_CONF_DIR"

            rejection_cases="$TMPDIR/nix-rejections.jsonl"
            ${pkgs.jq}/bin/jq -c \
              '.cases[] | select(.consumers | index("nix")) | select(.expected.outcome == "reject")' \
              ${../../tests/abilities/conformance/v1.json} > "$rejection_cases"

            tested=0
            while IFS= read -r case_json; do
              case_id="$(printf '%s\n' "$case_json" | ${pkgs.jq}/bin/jq -r '.id')"
              expected_code="$(printf '%s\n' "$case_json" | ${pkgs.jq}/bin/jq -r '.expected.code')"

              if diagnostic="$(${pkgs.nix}/bin/nix-instantiate \
                --eval --strict --json \
                --argstr caseJson "$case_json" \
                --argstr system ${lib.escapeShellArg pkgs.stdenv.buildPlatform.system} \
                ${directFixture}/direct.nix 2>&1)"; then
                echo "ability authoring case '$case_id' unexpectedly succeeded" >&2
                exit 1
              fi

              markers="$(printf '%s\n' "$diagnostic" \
                | ${pkgs.grep}/bin/grep -o 'AOS_ABILITY_DIAGNOSTIC_V1\[[a-z0-9-]*\]' \
                | ${pkgs.coreutils}/bin/sort -u || true)"
              if [ "$markers" != "AOS_ABILITY_DIAGNOSTIC_V1[$expected_code]" ]; then
                echo "ability authoring case '$case_id' returned '$markers', expected '$expected_code'" >&2
                printf '%s\n' "$diagnostic" >&2
                exit 1
              fi

              tested=$((tested + 1))
            done < "$rejection_cases"

            if [ "$tested" -eq 0 ]; then
              echo "ability authoring corpus contains no direct Nix rejection cases" >&2
              exit 1
            fi

            mkdir -p "$out"
            cp ${../../tests/abilities/conformance/v1.json} "$out/corpus.json"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
