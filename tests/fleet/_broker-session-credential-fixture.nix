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
  buildDeps = [pkgs.protobuf];
  runtimeDeps = [];
  cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
  postBuild = ''
    mkdir -p credential-fixture
    count=0
    artifact_dir="''${CARGO_TARGET_DIR:-target}/debug/deps"
    for candidate in "$artifact_dir"/aos_sandbox_broker_session_security-*; do
      if [ -f "$candidate" ] && [ -x "$candidate" ]; then
        install -m 0755 "$candidate" credential-fixture/broker-session-credential-fixture
        count=$((count + 1))
      fi
    done
    if [ "$count" -ne 1 ]; then
      echo "expected exactly one broker credential fixture, found $count" >&2
      exit 1
    fi
  '';
  postInstall = ''
    mkdir -p "$out/bin"
    install -m 0755 credential-fixture/broker-session-credential-fixture "$out/bin/"
  '';
}
