##! Native AOS handler for package-owned systemd abilities.
{
  lib,
  mkCargoPackage,
  aosWorkspaceSource,
  aosWorkspaceVendor,
  cmake,
  libssh2,
  openssl,
  perl,
  pkg-config,
  protobuf,
  sqlite,
  systemd,
  tpm2-tools,
  zlib,
}: let
  version = "0.1.0";
  src = aosWorkspaceSource;
  cargoDeps = aosWorkspaceVendor;
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "aos-systemd-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-systemd-provider";
      entryPoint = "bin/aos-systemd-provider";
    };

    inherit version src cargoDeps;
    cargoEnv = {
      OPENSSL_DIR = "${openssl}";
      OPENSSL_LIB_DIR = "${openssl}/lib";
      OPENSSL_INCLUDE_DIR = "${openssl}/include";
      OPENSSL_NO_VENDOR = "1";
      OPENSSL_STATIC = "0";
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      PROTOC = "${protobuf}/bin/protoc";
      AOS_SYSTEMD_CREDS = "${systemd}/bin/systemd-creds";
      AOS_SYSTEMD_PCREXTEND = "${systemd}/lib/systemd/systemd-pcrextend";
      AOS_TPM2_CREATEEK = "${tpm2-tools}/bin/tpm2_createek";
      AOS_TPM2_CREATEAK = "${tpm2-tools}/bin/tpm2_createak";
      AOS_TPM2_READPUBLIC = "${tpm2-tools}/bin/tpm2_readpublic";
      AOS_TPM2_QUOTE = "${tpm2-tools}/bin/tpm2_quote";
      AOS_TPM2_PCRREAD = "${tpm2-tools}/bin/tpm2_pcrread";
      AOS_TPM2_CHECKQUOTE = "${tpm2-tools}/bin/tpm2_checkquote";
      AOS_TPM2_FLUSHCONTEXT = "${tpm2-tools}/bin/tpm2_flushcontext";
    };
    cargoRoot = "crates";
    cargoFlags = "-p aos-systemd-provider";
    cargoTestFlags = "-p aos-systemd-provider";
    doCheck = true;

    buildDeps = [cmake perl pkg-config protobuf];
    runtimeDeps = [libssh2 openssl sqlite systemd tpm2-tools zlib];

    meta = {
      description = "Authenticated systemd ability provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-systemd-provider";
    };
  }
