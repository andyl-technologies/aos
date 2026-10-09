##! Checks native mount, swap, and timer definitions with the retained systemd parser.
{pkgs}:
pkgs.mkAosCargoPackage {
  pname = "aos-systemd-native-unit-parser-check";
  version = "0";
  cargoDeps = pkgs.aos.passthru.cargoDeps;
  cargoEnv =
    pkgs.aos.passthru.cargoEnv
    // {
      AOS_SYSTEMD_ANALYZE = "${pkgs.systemd}/bin/systemd-analyze";
      AOS_SYSTEMD_UNIT_PATH = "${pkgs.systemd}/lib/systemd/system";
      AOS_SYSTEMD_PARSER_SHELL = "${pkgs.bash}/bin/bash";
    };
  cargoRoot = "crates";
  cargoFlags = "-p aos-systemd-provider";
  cargoBuildCommands = [
    "test --no-run --release --frozen --offline -j$NIX_BUILD_CORES -p aos-systemd-provider --bin aos-systemd-native-resource-provider --features systemd-parser-tests"
  ];
  cargoTestFlags = "-p aos-systemd-provider --bin aos-systemd-native-resource-provider --features systemd-parser-tests resource_effects::unit::parser_tests:: -- --nocapture";
  buildDeps = [pkgs.cmake pkgs.perl pkgs.pkg-config pkgs.protobuf pkgs.systemd pkgs.bash];
  runtimeDeps = [pkgs.openssl pkgs.sqlite pkgs.libssh2 pkgs.zlib];
  installBins = false;
  doCheck = true;
}
