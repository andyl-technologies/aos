##! Builds the source-built native boot adoption acceptance harness.
{
  mkAosCargoPackage,
  aosWorkspaceVendor,
  buildPackages,
  openssl,
  sqlite,
  libssh2,
  zlib,
}:
mkAosCargoPackage {
  pname = "aos-boot-configuration-test-driver";
  version = "0";
  platformSupport = {
    build = [
      {
        abi = ["gnu"];
        os = ["linux"];
      }
    ];
    host = [
      {
        abi = ["gnu"];
        cpu = ["x86_64" "aarch64"];
        os = ["linux"];
      }
    ];
    target = [];
    role = "build-input";
  };
  cargoDeps = aosWorkspaceVendor;
  cargoRoot = "crates";
  cargoBuildCommands = ["test --release --frozen --offline --no-run -p aos-package --lib"];
  doCheck = false;
  buildDeps = [buildPackages.pkg-config buildPackages.protobuf buildPackages.cmake buildPackages.perl];
  runtimeDeps = [openssl sqlite libssh2 zlib];
  cargoEnv = {
    OPENSSL_DIR = "${openssl}";
    OPENSSL_LIB_DIR = "${openssl}/lib";
    OPENSSL_INCLUDE_DIR = "${openssl}/include";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";
  };
  meta = {
    description = "Checks native boot metadata source adoption and recovery";
    license = "Apache-2.0";
  };
}
