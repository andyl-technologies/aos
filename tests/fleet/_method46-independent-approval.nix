# Host-only independent signer. The private operator seed is a runtime input.
{
  lib,
  pkgs,
}:
pkgs.mkCargoPackage {
  pname = "aos-method46-independent-approval";
  version = "1";
  src = import ../../pkgs/tools/aos/_workspace-source.nix {
    inherit lib;
    extraPaths = ["tests/sandbox/method46-independent-approval.rs"];
  };
  cargoDeps = pkgs.aos.passthru.cargoDeps;
  cargoRoot = "crates";
  buildType = "debug";
  cargoFlags = "-p aos-sandbox-service-journal-probe --bin aos-method46-independent-approval";
  cargoTestFlags = "-p aos-sandbox-service-journal-probe --bin aos-method46-independent-approval";
  postPatch = ''
    cp tests/sandbox/method46-independent-approval.rs \
      crates/sandbox/controller/aos-sandbox-controller-domain/tests/fixtures/service-journal/src/bin/aos-method46-independent-approval.rs
  '';
  buildDeps = [pkgs.protobuf];
  cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
  runtimeDeps = [];
}
