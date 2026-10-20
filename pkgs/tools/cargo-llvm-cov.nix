##! cargo-llvm-cov — source-based code coverage for Cargo projects.
{
  lib,
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
  bash,
  llvm,
}: let
  version = "0.9.1";

  # Upstream does not commit Cargo.lock; the published crate carries the
  # lockfile that its release binaries were built and tested with.
  src = fetchurl {
    urls = ["https://static.crates.io/crates/cargo-llvm-cov/cargo-llvm-cov-${version}.crate"];
    name = "cargo-llvm-cov-${version}.tar.gz";
    hash = "sha256-XgBkfMkpQMTdgiScSA/gj9OAl2fonwVrzsRtinli6ls=";
  };
in
  mkCargoPackage {
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
      role = "public-package";
    };
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The installed target command and its offline query.";
        operation = "Execute the packaged command without network or persistent state.";
        expected = "The target command reports its documented query result.";
        files = {};
        steps = [
          {
            argv = ["@python@" "-c" "import subprocess\nresult = subprocess.run(['@out@/bin/cargo-llvm-cov', 'llvm-cov', '--version'], capture_output=True, text=True)\nassert result.returncode == 0 and ('cargo-llvm-cov' in result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint('cargo-llvm-cov command passed')\n"];
            exit_code = 0;
            stdout.exact = "cargo-llvm-cov command passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "An unknown command option or variable.";
        operation = "Parse and reject the invalid request.";
        expected = "The target command fails before performing the operation.";
        files = {};
        steps = [
          {
            argv = ["@python@" "-c" "import subprocess, sys\nresult = subprocess.run(['@out@/bin/cargo-llvm-cov', 'llvm-cov', '--aos-invalid-option'], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write('cargo-llvm-cov rejected invalid input\\n')\nraise SystemExit(7)\n"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "cargo-llvm-cov rejected invalid input\n";
          }
        ];
        artifacts = [];
      };
    };
    pname = "cargo-llvm-cov";
    inherit src;
    # Keep compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "cargo-llvm-cov-${version}-vendor";
      hash = "sha256-uSMRu+OjdEyxYyGc65Z5vYOcHyOcgf1L3Kxc4QHRM2o=";
    };
    cargoFlags = "--bin cargo-llvm-cov";

    # The tests build fixture projects with instrumented compilers and compare
    # against snapshot reports produced by rustup's llvm-tools component.
    doCheck = false;

    runtimeDeps = [llvm];

    # The AOS Rust toolchain links against the AOS LLVM rather than shipping
    # rustup's llvm-tools component, so cargo-llvm-cov cannot find llvm-cov
    # and llvm-profdata in the sysroot. Default both to the matching LLVM
    # while letting a caller override them.
    postInstall = ''
      mv "$out/bin/cargo-llvm-cov" "$out/bin/.cargo-llvm-cov-wrapped"
      cat > "$out/bin/cargo-llvm-cov" <<WRAPPER
      #!${bash}/bin/bash
      export LLVM_COV="\''${LLVM_COV:-${llvm}/bin/llvm-cov}"
      export LLVM_PROFDATA="\''${LLVM_PROFDATA:-${llvm}/bin/llvm-profdata}"
      exec "$out/bin/.cargo-llvm-cov-wrapped" "\$@"
      WRAPPER
      chmod 755 "$out/bin/cargo-llvm-cov"

      "$out/bin/cargo-llvm-cov" llvm-cov --version

      mkdir -p "$out/share/licenses/cargo-llvm-cov"
      cp LICENSE-APACHE LICENSE-MIT "$out/share/licenses/cargo-llvm-cov/"
    '';

    meta = {
      description = "Cargo subcommand for LLVM source-based code coverage";
      homepage = "https://github.com/taiki-e/cargo-llvm-cov";
      license = "Apache-2.0 OR MIT";
      mainProgram = "cargo-llvm-cov";
    };
  }
