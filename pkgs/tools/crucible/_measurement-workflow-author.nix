# Builds only the immutable workflow author; it issues no runtime credit.
{
  pkgs,
  lib,
}: let
  source = import ./_source.nix {inherit lib;};
in
  pkgs.mkCargoPackage {
    pname = "crucible-private-measurement-workflow-author";
    version = "0";
    src = source;
    cargoDeps = pkgs.crucible-controller.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoEnv = {
      OPENSSL_DIR = "${pkgs.openssl}";
      OPENSSL_LIB_DIR = "${pkgs.openssl}/lib";
      OPENSSL_INCLUDE_DIR = "${pkgs.openssl}/include";
      OPENSSL_NO_VENDOR = "1";
      OPENSSL_STATIC = "0";
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      PROTOC = "${pkgs.protobuf}/bin/protoc";
    };
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p crucible-daemon --bin crucible-measurement-workflow --features private-measurement-domain"
    ];
    doCheck = false;
    buildDeps = [pkgs.rust.dev pkgs.pkg-config pkgs.protobuf];
    runtimeDeps = [pkgs.openssl pkgs.sqlite];
  }
