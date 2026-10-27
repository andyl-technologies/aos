# Host-only native history DATA; the installed Source requalifies custody.
{
  lib,
  pkgs,
}:
pkgs.mkCargoPackage {
  pname = "aos-method46-external-history";
  version = "1";
  src = import ../../pkgs/tools/aos/_workspace-source.nix {
    inherit lib;
    extraPaths = ["tests/sandbox/method46-external-history.rs"];
  };
  cargoDeps = pkgs.aos.passthru.cargoDeps;
  cargoRoot = "crates";
  buildType = "debug";
  cargoFlags = "-p aos-sandbox-service-journal-probe --bin aos-method46-external-history --features aos-sandbox-controller-domain/test-fixtures";
  cargoTestFlags = "-p aos-sandbox-service-journal-probe --bin aos-method46-external-history --features aos-sandbox-controller-domain/test-fixtures";
  postPatch = ''
    cp tests/sandbox/method46-external-history.rs \
      crates/sandbox/controller/aos-sandbox-controller-domain/tests/fixtures/service-journal/src/bin/aos-method46-external-history.rs
  '';
  buildDeps = [pkgs.protobuf];
  cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
  runtimeDeps = [];
}
