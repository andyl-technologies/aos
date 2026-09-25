{
  pkgs,
  e2eDeterminism,
  campaignGateMatrix,
  campaignOperationalContinuity,
  campaignFindingPortability,
  hotForkScaling,
  requiredGates,
  cruciblePackage,
  releaseManifest,
  releaseAcceptanceContract,
}: let
  runner = ./_phase9-campaign-release-acceptance.sh;
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-release-acceptance";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.bash
      pkgs.coreutils
      pkgs.grep
      pkgs.sed
      e2eDeterminism
      campaignGateMatrix
      campaignOperationalContinuity
      campaignFindingPortability
      hotForkScaling
      requiredGates
      cruciblePackage
      releaseManifest
      releaseAcceptanceContract
    ];

    phases = [
      {
        name = "validate-release-acceptance";
        script = ''
          set -eu
          ${pkgs.bash}/bin/bash ${runner} \
            ${e2eDeterminism} \
            ${campaignGateMatrix} \
            ${campaignOperationalContinuity} \
            ${campaignFindingPortability} \
            ${hotForkScaling} \
            ${requiredGates} \
            ${cruciblePackage} \
            ${releaseManifest} \
            ${releaseAcceptanceContract} \
            "$out"

          mkdir -p "$out/contracts"
          cp ${./campaign-release-acceptance-contract.toml} \
            "$out/contracts/release-acceptance.toml"
          cp ${releaseAcceptanceContract}/result \
            "$out/contracts/release-acceptance-validator.result"
        '';
      }
    ];
  }
