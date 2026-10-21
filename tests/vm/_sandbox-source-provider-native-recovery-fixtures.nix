# Builds test-only fixed-owner recovery fixtures for both VM drivers.
{
  lib,
  pkgs,
}:
pkgs.mkCargoPackage {
  pname = "aos-sandbox-source-provider-native-recovery-vm-fixtures";
  version = "0.0.0";
  src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
  cargoDeps = pkgs.aos.passthru.cargoDeps;
  cargoRoot = "crates";
  buildType = "debug";
  cargoBuildCommands = [
    "build --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-service-journal-probe --features aos-sandbox-service-journal-probe/native-recovery-vm-fixture --bin aos-sandbox-source-provider-credentials-vm-probe --bin aos-sandbox-source-provider-precut-vm-seed --bin aos-sandbox-source-provider-owner-vm-server"
    "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-mount"
  ];
  doCheck = false;
  buildDeps = [pkgs.protobuf];
  cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
  runtimeDeps = [];
  postInstall = ''
    count=0
    for candidate in target/debug/deps/aos_sandbox_mount-*; do
      if [ -f "$candidate" ] && [ -x "$candidate" ]; then
        install -m 0755 "$candidate" "$out/bin/aos-sandbox-mount-native-recovery-vm-tests"
        count=$((count + 1))
      fi
    done
    if [ "$count" -ne 1 ]; then
      echo "expected one Mount unit-test executable, found $count" >&2
      exit 1
    fi
  '';
}
