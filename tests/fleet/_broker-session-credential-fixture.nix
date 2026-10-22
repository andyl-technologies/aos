# VM-only executable that provisions fresh broker-session and Host authority credentials.
{
  lib,
  pkgs,
}:
pkgs.mkCargoPackage {
  pname = "aos-broker-session-credential-fixture";
  version = "0.1.0";
  src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
  cargoDeps = pkgs.aos-sandbox-mountd.passthru.cargoDeps;
  cargoRoot = "crates";
  buildType = "debug";
  cargoBuildCommands = [
    "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --features aos-sandbox-broker-session-security/kernel-tests"
  ];
  doCheck = false;
  installBins = false;
  buildDeps = [pkgs.protobuf pkgs.jq];
  runtimeDeps = [];
  cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
  postBuild = import ./_cargo-libtest-artifact.nix {
    inherit lib pkgs;
    crate = "aos-sandbox-broker-session-security";
    destination = "credential-fixture/broker-session-credential-fixture";
  };
  postInstall = ''
    mkdir -p "$out/bin"
    install -m 0755 credential-fixture/broker-session-credential-fixture "$out/bin/"
  '';
}
