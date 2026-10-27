{
  pkgs,
  lib,
}:
pkgs.mkDerivation {
  pname = "crucible-phase1-node-contract-requirement-map";
  version = "0";
  src = null;

  buildDeps = [pkgs.coreutils pkgs.python3];

  phases = [
    {
      name = "check-requirement-index";
      script = ''
        set -eu
        export PYTHONDONTWRITEBYTECODE=1
        mkdir -p checker "$out"
        cp ${./node_contract_requirement_map.py} checker/node_contract_requirement_map.py
        cp ${./node_contract_requirement_map_test.py} checker/node_contract_requirement_map_test.py
        ${pkgs.python3}/bin/python3 checker/node_contract_requirement_map_test.py
        ${pkgs.python3}/bin/python3 checker/node_contract_requirement_map.py \
          --rfc-dir ${../../docs/rfcs/0025-crucible-node-contract} \
          --plan ${../../docs/plans/crucible-node-contract/phased-implementation.md} \
          --map ${../../docs/plans/crucible-node-contract/requirement-map.tsv} \
          --output "$out/requirement-index.json"

        cat > "$out/result" <<'RESULT'
        PASS
        check=checks.crucible.phase1.nodeContractRequirementMap
        scope=documentation-consistency
        RESULT
      '';
    }
  ];
}
