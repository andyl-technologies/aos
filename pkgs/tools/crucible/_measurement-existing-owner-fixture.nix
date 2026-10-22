# Composes the private registered-owner fixture without creating a new launcher.
{
  pkgs,
  lib,
  installedImages,
  operatorPolicy,
  imageInventory,
  sourceManifest,
  nativeCount,
  servicePolicy,
  sqliteBootstrapProof,
  campaignPolicy,
  componentAuthorities,
  guestAssets,
  imageBytes,
  operatorMode,
  kernel,
  initrd,
  externalSource,
  dependencyRoots,
  process,
}: let
  workflow = import ./_measurement-workflow.nix {
    inherit pkgs lib nativeCount servicePolicy sqliteBootstrapProof campaignPolicy componentAuthorities guestAssets;
  };
  ownedRootfs = import ./_measurement-owned-rootfs.nix {
    inherit pkgs lib installedImages operatorPolicy imageInventory sourceManifest workflow imageBytes operatorMode;
  };
  parentFixture = import ./_measurement-parent.nix {
    inherit pkgs lib ownedRootfs kernel initrd externalSource dependencyRoots operatorPolicy sourceManifest workflow;
    actorInventory = imageInventory;
  };
  service = import ./_measurement-parent-service.nix {
    inherit pkgs parentFixture process;
  };
in {
  inherit ownedRootfs parentFixture;
  serviceModule = service;
  privateFixture = true;
  runtimeAdmission = false;
}
