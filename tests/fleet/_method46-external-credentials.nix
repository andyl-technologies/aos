# Runtime external inputs; no fixture secret is included in an installed image.
{
  lib,
  pkgs,
}:
pkgs.mkCargoPackage {
  pname = "aos-method46-external-credentials";
  version = "1";
  src = import ../../pkgs/tools/aos/_workspace-source.nix {
    inherit lib;
    extraPaths = ["tests/sandbox/method46-external-credentials.rs"];
  };
  cargoDeps = pkgs.aos.passthru.cargoDeps;
  cargoRoot = "crates";
  buildType = "debug";
  cargoFlags = "-p aos-sandbox-service-journal-probe --bin aos-method46-external-credentials";
  cargoTestFlags = "-p aos-sandbox-service-journal-probe --bin aos-method46-external-credentials";
  postPatch = ''
    cp tests/sandbox/method46-external-credentials.rs \
      crates/sandbox/controller/aos-sandbox-controller-domain/tests/fixtures/service-journal/src/bin/aos-method46-external-credentials.rs
  '';
  buildDeps = [pkgs.protobuf];
  cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
  runtimeDeps = [];
}
