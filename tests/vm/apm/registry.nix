# Registry VM suite, composed by workflow with stable public check names.
{
  testing,
  pkgs,
  aosPkg,
}: let
  shared = import ./registry/fixtures.nix {inherit pkgs aosPkg;};
in
  (import ./registry/lifecycle.nix {
    inherit testing;
    inherit (shared) fixtures;
  })
  // (import ./registry/publish.nix {
    inherit testing pkgs aosPkg;
    inherit (shared) fixtures publishDeps publishSysrootImage publishSysrootDisk publishSysrootInfo publishSysrootUki setupNixPublishEnv setupAltNixPublishEnv;
  })
  // (import ./registry/unpublish.nix {
    inherit testing pkgs;
    inherit (shared) fixtures setupNixPublishEnv closureLeafTool closureRootTool retireDepTool retireTool closureWorkflowDeps;
  })
  // (import ./registry/system-config.nix {
    inherit testing pkgs;
    inherit (shared) fixtures maintainerWorkflowDeps setupNixPublishEnv closureLeafTool closureRootTool;
  })
  // (import ./registry/origin-defaults.nix {
    inherit testing pkgs;
    inherit (shared) fixtures maintainerWorkflowDeps setupNixPublishEnv closureLeafTool closureRootTool;
  })
  // (import ./registry/maintainer.nix {
    inherit testing pkgs;
    inherit (shared) fixtures maintainerWorkflowDeps setupNixPublishEnv maintRunnerDepTool maintRunnerTool;
  })
  // (import ./registry/static-origin.nix {
    inherit testing pkgs;
    inherit (shared) fixtures maintainerWorkflowDeps setupNixPublishEnv closureLeafTool closureRootTool closureRootSourceTool closureLeafToolV2 closureRootToolV2 closureRootSourceToolV2;
  })
  // (import ./registry/channels.nix {
    inherit testing pkgs;
    inherit (shared) fixtures maintainerWorkflowDeps setupNixPublishEnv closureLeafTool closureRootTool closureLeafToolV2 closureRootToolV2 closureLeafToolV3 closureRootToolV3;
  })
  // (import ./registry/branches.nix {
    inherit testing pkgs;
    inherit (shared) fixtures setupNixPublishEnv closureLeafTool closureRootTool closureWorkflowDeps;
  })
  // (import ./registry/validation-bundles.nix {
    inherit testing pkgs;
    inherit (shared) fixtures setupNixPublishEnv closureLeafTool closureRootTool closureWorkflowDeps;
  })
  // (import ./registry/signed-commits.nix {
    inherit testing pkgs;
    inherit (shared) fixtures maintainerWorkflowDeps setupNixPublishEnv signedLeafToolV1 signedToolV1 signedLeafToolV2 signedToolV2 signedLeafToolV3 signedToolV3 signedLeafToolV4 signedToolV4 signedLeafToolV5 signedToolV5;
  })
  // (import ./registry/trust-changes.nix {
    inherit testing pkgs;
    inherit (shared) fixtures;
  })
  // (import ./registry/closures.nix {
    inherit testing pkgs;
    inherit (shared) fixtures setupNixPublishEnv closureLeafTool closureRootTool closureWorkflowDeps;
  })
