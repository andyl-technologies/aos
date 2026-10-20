# Guest Cargo invocations need the compiler and library settings that ordinary
# derivation builders receive from stdenv. Retain the same AOS SQLite linkage.
{
  pkgs,
  lib,
}: {
  runtimeInputs = [pkgs.gcc pkgs.pkg-config pkgs.sqlite];
  runtimeEnvironment = {
    CC = "${pkgs.gcc}/bin/cc";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    PKG_CONFIG_PATH = lib.makePkgConfigPath [pkgs.sqlite];
    RUSTFLAGS = "-C link-arg=-Wl,-rpath,${pkgs.sqlite}/lib";
  };
}
