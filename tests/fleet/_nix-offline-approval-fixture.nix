# Host-only independent approval signer; its private key never enters a VM.
{
  lib,
  pkgs,
}:
pkgs.mkCargoPackage {
  pname = "aos-sandbox-nix-offline-approval-vm-fixture";
  version = "0.0.0";
  src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
  cargoDeps = pkgs.aos.passthru.cargoDeps;
  cargoRoot = "crates";
  buildType = "debug";
  cargoFlags = "-p aos-sandbox-service-journal-probe --bin aos-sandbox-nix-offline-approval-vm-fixture";
  doCheck = false;
  buildDeps = [pkgs.protobuf];
  cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
  runtimeDeps = [];
}
