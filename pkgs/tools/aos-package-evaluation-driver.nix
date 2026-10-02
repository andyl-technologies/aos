##! Builds the production package-evaluation fixture driver from source.
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
  pname = "native-config-evaluation-driver";
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
  cargoFlags = "-p aos-package --example package_deployment_check";
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
    description = "Exercises admitted native package evaluation without activating effects";
    license = "Apache-2.0";
    mainProgram = "package_deployment_check";
  };
}
