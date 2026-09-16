##! aos-metadata-provider - typed platform acquisition and provisioning policy
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceSource,
  aosWorkspaceVendor,
  cmake,
  libssh2,
  openssl,
  pkg-config,
  protobuf,
  sqlite,
  stdenv,
  buildPackages,
  zlib,
}: let
  version = "0.1.0";
  src = aosWorkspaceSource;
  cargoDeps = aosWorkspaceVendor;
  isCross = stdenv.isCross;
  buildCmake =
    if isCross
    then buildPackages.cmake
    else cmake;
  buildPkgConfig =
    if isCross
    then buildPackages.pkg-config
    else pkg-config;
  buildProtobuf =
    if isCross
    then buildPackages.protobuf
    else protobuf;
  cargoEnv = {
    OPENSSL_DIR = "${openssl}";
    OPENSSL_LIB_DIR = "${openssl}/lib";
    OPENSSL_INCLUDE_DIR = "${openssl}/include";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    PROTOC = "${buildProtobuf}/bin/protoc";
  };
  cargoArtifactContract = {
    family = "aos-metadata-provider-release-and-test";
    checkType = "debug";
    nativeInputs = map toString [openssl sqlite buildProtobuf buildCmake libssh2];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-metadata-provider-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-metadata-provider-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-metadata-provider"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-metadata -p aos-metadata-provider"
    ];
    inherit cargoEnv;
    buildDeps = [buildPkgConfig buildProtobuf buildCmake];
    runtimeDeps = [openssl sqlite libssh2 zlib];
  };
in
  mkCargoPackage {
    pname = "aos-metadata-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-metadata-acquisition-provider";
      entryPoint = "bin/aos-metadata-acquisition-provider";
    };

    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoNextest = true;
    cargoFlags = "-p aos-metadata-provider";
    cargoTestFlags = "-p aos-metadata -p aos-metadata-provider";
    doCheck = true;
    buildDeps = [buildPkgConfig buildProtobuf buildCmake];
    runtimeDeps = [openssl sqlite libssh2 zlib];

    abilities = ./_aos-metadata-provider;

    postInstall = ''
      test -x "$out/bin/aos-metadata-acquisition-provider"
      test -x "$out/bin/aos-metadata-policy-provider"
    '';

    meta = {
      description = "Typed platform metadata acquisition and provisioning policy provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
    };
  }
