{
  pkgs,
  lib,
  requiredClaims,
  requiredStatuses ? [],
  contractPath ? ./campaign-release-acceptance-contract.toml,
  attrPath ? "checks.crucible.phase9.gates.campaignRequiredGates",
}: let
  contract = builtins.fromTOML (builtins.readFile contractPath);
  claimCount = builtins.length requiredClaims;
  claimNames = map (claim: claim.gate) requiredClaims;
  expectedClaimNames = contract.executable_evidence.required_claim_gates;
  uniqueClaimNames = lib.unique claimNames;
  invalidClaims =
    builtins.filter (
      claim:
        !(lib.isDerivation claim.result)
        || !(builtins.isList claim.requiredLines)
        || claim.requiredLines == []
    )
    requiredClaims;
  invalidStatuses = builtins.filter (status: !(lib.isDerivation status)) requiredStatuses;
  renderClaim = claim: let
    resultPath = "${claim.result}/result";
    resultName = "${builtins.replaceStrings [":"] ["-"] claim.gate}.result";
  in ''
    test -f ${resultPath}
    test ! -L ${resultPath}
    test "$(sed -n '1p' ${resultPath})" = PASS
    ${builtins.concatStringsSep "\n" (map (line: ''
        test "$(grep -Fxc ${lib.escapeShellArg line} ${resultPath} || true)" -eq 1
      '')
      claim.requiredLines)}
    cp ${resultPath} "$out/results/${resultName}"
    result_sha256=$(sha256sum "$out/results/${resultName}" | cut -d ' ' -f 1)
    printf '%s\t%s\n' ${lib.escapeShellArg claim.gate} "$result_sha256" \
      >> "$out/manifest.tsv"
  '';
in
  if invalidClaims != []
  then throw "campaign required-gate aggregate contains an invalid claim"
  else if invalidStatuses != []
  then throw "campaign required-gate aggregate contains an invalid gate status"
  else if claimCount != builtins.length uniqueClaimNames
  then throw "campaign required-gate aggregate contains a duplicate claim"
  else if claimNames != expectedClaimNames
  then throw "campaign required-gate aggregate differs from the release contract"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-required-gates";
      version = "0";
      src = null;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.grep
          pkgs.sed
        ]
        ++ map (claim: claim.result) requiredClaims
        ++ requiredStatuses;

      phases = [
        {
          name = "authenticate-required-gates";
          script = ''
            set -eu
            mkdir -p "$out/results"
            printf 'gate\tresult_sha256\n' > "$out/manifest.tsv"
            printf '%s\n' ${builtins.concatStringsSep " " (map lib.escapeShellArg expectedClaimNames)} \
              > "$out/required-claim-gates.txt"

            ${builtins.concatStringsSep "\n" (map renderClaim requiredClaims)}

            test "$(wc -l < "$out/manifest.tsv" | tr -d ' ')" \
              -eq ${toString (claimCount + 1)}
            test "$(cut -f1 "$out/manifest.tsv" | sed -n '2,$p' | sort -u | wc -l | tr -d ' ')" \
              -eq ${toString claimCount}
            manifest_sha256=$(sha256sum "$out/manifest.tsv" | cut -d ' ' -f 1)
            claim_inventory_sha256=$(sha256sum "$out/required-claim-gates.txt" | cut -d ' ' -f 1)

            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            gate=gate:campaign-required-gates
            required_claim_count=${toString claimCount}
            all_required_claims_authenticated=true
            manifest_sha256=$manifest_sha256
            required_claim_gates_sha256=$claim_inventory_sha256
            RESULT
          '';
        }
      ];
    }
