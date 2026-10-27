##! Independently linked Apache helper for GPL process-based engine cross-checks.
{
  lib,
  stdenv,
  mkCargoPackage,
  aosWorkspaceVendor,
  rust,
  pkg-config,
  openssl,
  sqlite,
  buildPackages,
}: let
  buildRustDev =
    if stdenv.isCross
    then buildPackages.rust.dev
    else rust.dev;
  buildPkgConfig =
    if stdenv.isCross
    then buildPackages.pkg-config
    else pkg-config;
in
  mkCargoPackage {
    pname = "crucible-qemu-test-oracle";
    version = "0.1.0";
    src = import ./_source.nix {inherit lib;};
    cargoDeps = aosWorkspaceVendor;
    cargoWorkspaceMembers = import ./_workspace.nix {inherit lib;};
    cargoRoot = "crates";
    cargoFlags = "-p crucible-control-server --bin crucible-qemu-test-oracle --features qemu-test-oracle";
    doCheck = false;
    buildDeps = [buildRustDev buildPkgConfig openssl sqlite];
    runtimeDeps = [openssl sqlite];
  }
