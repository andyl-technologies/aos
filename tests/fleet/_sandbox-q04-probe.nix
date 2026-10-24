# Builds the protected-owner fixture commands; these issue no startup grants.
{
  lib,
  pkgs,
}:
pkgs.mkCargoPackage {
  pname = "aos-sandbox-q04-bootstrap-vm-probe";
  version = "0.0.0";
  src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
  cargoDeps = pkgs.aos.passthru.cargoDeps;
  cargoRoot = "crates";
  buildType = "debug";
  cargoFlags = "-p aos-sandbox-service-journal-probe --bin aos-sandbox-q04-bootstrap-vm-probe --bin aos-sandbox-cache-physical-join-vm-probe";
  doCheck = false;
  buildDeps = [pkgs.protobuf];
  cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
  runtimeDeps = [];
}
