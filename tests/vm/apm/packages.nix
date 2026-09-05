# Packages VM suite, composed by workflow with stable public check names.
{
  testing,
  pkgs,
  aosPkg,
}: let
  shared = import ./packages/fixtures.nix {inherit pkgs aosPkg;};
in
  (import ./packages/install.nix {
    inherit testing pkgs;
    inherit (shared) fixtures installBasicTool installDepTool installWithDepsTool realInstallDeps setupNixEnv;
  })
  // (import ./packages/idempotency.nix {
    inherit testing pkgs;
    inherit (shared) fixtures idempotentTool idempotentWrapper realIdempotentDeps setupNixEnv;
  })
  // (import ./packages/download-reinstall.nix {
    inherit testing pkgs;
    inherit (shared) fixtures idempotentTool downloadOnlyWrapper reinstallTool reinstallPeerTool realDownloadOnlyDeps realReinstallDeps setupNixEnv;
  })
  // (import ./packages/remove.nix {
    inherit testing pkgs;
    inherit (shared) fixtures idempotentTool removeLeftTool removeRightTool removeBasicTool realRemoveDeps setupNixEnv;
  })
  // (import ./packages/registry-recovery.nix {
    inherit testing pkgs;
    inherit (shared) fixtures installBasicTool realInstallDeps setupNixEnv;
  })
  // (import ./packages/upgrade.nix {
    inherit testing pkgs;
    inherit (shared) fixtures upgradeAlphaV1 upgradeAlphaV2 upgradeBetaV1 upgradeBetaV2 realUpgradeDeps setupNixEnv;
  })
  // (import ./packages/rollback.nix {
    inherit testing pkgs;
    inherit (shared) fixtures rollbackToolV1 rollbackToolV2 rollbackToolV3 realRollbackDeps setupNixEnv;
  })
  // (import ./packages/closure-lifecycle.nix {
    inherit testing pkgs;
    inherit (shared) fixtures realLifecycleDeps setupNixEnv;
  })
  // (import ./packages/alternate-state.nix {
    inherit testing pkgs;
    inherit (shared) fixtures sourcefulV1 sourceVerifyAltDeps gcAltDeps setupAltNixEnv setupEmptyAltNixGcEnv;
  })
  // (import ./packages/command-surface.nix {
    inherit testing pkgs;
    inherit (shared) fixtures surfaceLeafTool surfaceTool surfaceUpgradeV1 surfaceUpgradeV2 sourcefulV1 sourcefulV2 sourcefulSourceV1 sourcefulSourceV2 sourceClosureRuntime sourceClosureSourceDep sourceClosureSourceRoot realCommandSurfaceDeps setupNixEnv;
  })
  // (import ./packages/hold.nix {
    inherit testing pkgs;
    inherit (shared) fixtures holdToolV1 holdToolV2 realHoldDeps setupNixEnv;
  })
