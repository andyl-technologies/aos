{
  pkgs,
  lib,
  operatorEvidence,
  destructiveRecoveryEvidence,
  dogfoodEvidence,
  e2eEvidence,
  campaignGateMatrix,
  campaignOperationalContinuity,
  campaignFindingPortability,
  hotForkScaling,
  cruciblePackage,
  releaseManifest,
  trustedAllowedSigners,
}: let
  runner = ./_phase9-campaign-release-acceptance.sh;
  releaseAcceptanceContractPath = ./campaign-release-acceptance-contract.toml;
  releaseAcceptanceContract = import ./phase9-campaign-release-acceptance-contract.nix {
    inherit pkgs;
  };
  evidenceSpec = kind: contractPath:
    import ./_campaign-manual-evidence-spec.nix {
      inherit lib kind contractPath releaseAcceptanceContractPath;
    };
  operatorContract = ../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-acceptance-contract.toml;
  destructiveRecoveryContract = ../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-destructive-recovery-contract.toml;
  dogfoodContract = ../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-dogfood-contract.toml;
  e2eContract = ./e2e-determinism-evidence-contract.toml;
  operatorSpec = evidenceSpec "operator" operatorContract;
  destructiveRecoverySpec = evidenceSpec "destructive-recovery" destructiveRecoveryContract;
  dogfoodSpec = evidenceSpec "dogfood" dogfoodContract;
  e2eSpec = evidenceSpec "e2e-determinism" e2eContract;
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-release-acceptance";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.bash
      pkgs.coreutils
      pkgs.findutils
      pkgs.grep
      pkgs.openssh
      pkgs.sed
      operatorEvidence
      destructiveRecoveryEvidence
      dogfoodEvidence
      e2eEvidence
      campaignGateMatrix
      campaignOperationalContinuity
      campaignFindingPortability
      hotForkScaling
      cruciblePackage
      releaseManifest
      releaseAcceptanceContract
      trustedAllowedSigners
    ];

    phases = [
      {
        name = "validate-release-acceptance";
        script = ''
          set -eu
          ${pkgs.bash}/bin/bash ${runner} \
            ${operatorEvidence} \
            ${operatorSpec} \
            ${destructiveRecoveryEvidence} \
            ${destructiveRecoverySpec} \
            ${dogfoodEvidence} \
            ${dogfoodSpec} \
            ${e2eEvidence} \
            ${e2eSpec} \
            ${campaignGateMatrix} \
            ${campaignOperationalContinuity} \
            ${campaignFindingPortability} \
            ${hotForkScaling} \
            ${cruciblePackage} \
            ${releaseManifest} \
            ${releaseAcceptanceContract} \
            ${trustedAllowedSigners} \
            "$out"

          mkdir -p "$out/contracts"
          cp ${operatorContract} "$out/contracts/operator.toml"
          cp ${destructiveRecoveryContract} "$out/contracts/destructive-recovery.toml"
          cp ${dogfoodContract} "$out/contracts/dogfood.toml"
          cp ${e2eContract} "$out/contracts/e2e-determinism.toml"
          cp ${releaseAcceptanceContractPath} "$out/contracts/release-acceptance.toml"
          cp ${releaseAcceptanceContract}/result \
            "$out/contracts/release-acceptance-validator.result"
          cp ${operatorSpec} "$out/contracts/operator-evidence-spec.tsv"
          cp ${destructiveRecoverySpec} "$out/contracts/destructive-recovery-evidence-spec.tsv"
          cp ${dogfoodSpec} "$out/contracts/dogfood-evidence-spec.tsv"
          cp ${e2eSpec} "$out/contracts/e2e-determinism-evidence-spec.tsv"
        '';
      }
    ];
  }
