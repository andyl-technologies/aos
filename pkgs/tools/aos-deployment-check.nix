##! Native package deployment validation for source-built artifact producers.
{
  lib,
  mkAosCargoPackage,
  aosWorkspaceVendor,
  buildPackages,
  openssl,
  sqlite,
  libssh2,
  zlib,
}:
mkAosCargoPackage {
  pname = "aos-deployment-check";
  version = "0.1.0";
  cargoDeps = aosWorkspaceVendor;
  cargoRoot = "crates";
  cargoFlags = "-p aos-package --bin aos-deployment-check";
  cargoTestFlags = "-p aos-package --bin aos-deployment-check";
  doCheck = true;
  buildDeps = [buildPackages.pkg-config buildPackages.protobuf buildPackages.cmake buildPackages.perl];
  runtimeDeps = [openssl sqlite libssh2 zlib];
  cargoEnv = {
    OPENSSL_DIR = "${openssl}";
    OPENSSL_LIB_DIR = "${openssl}/lib";
    OPENSSL_INCLUDE_DIR = "${openssl}/include";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";
  };
  qualification.packageProbe = lib.qualification.commandProbe {
    primary = {
      input = "The native deployment validator executable.";
      operation = "Read its version without activation.";
      expected = "The validator identifies its native contract.";
      files = {};
      steps = [
        {
          argv = ["@out@/bin/aos-deployment-check" "--version"];
          exit_code = 0;
          stdout.exact = "aos-deployment-check 0.1.0\n";
        }
      ];
      artifacts = [];
    };
    badInput = {
      input = "An absent native deployment document.";
      operation = "Reject empty standard input.";
      expected = "Validation fails before any execution.";
      files = {};
      steps = [
        {
          argv = ["@out@/bin/aos-deployment-check"];
          stdin = "";
          exit_code = 1;
          observes_rejection = true;
        }
      ];
      artifacts = [];
    };
  };
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
  meta = {
    description = "Checks native package context, deferred graph, and generated reference identity";
    license = "Apache-2.0";
    mainProgram = "aos-deployment-check";
  };
}
