##! wasm-tools — inspect, validate, and transform WebAssembly modules and components.
{
  lib,
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
}: let
  version = "1.259.0";
  src = fetchurl {
    urls = ["https://github.com/bytecodealliance/wasm-tools/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-w+5/B1fRIgvUtGJgxPrUVJzuohH5HXBmScG6JMp/3Bc=";
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
            argv = ["@python@" "-c" "import subprocess\nresult = subprocess.run(['@out@/bin/wasm-tools', '--version'], capture_output=True, text=True)\nassert result.returncode == 0 and ('wasm-tools' in result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint('wasm-tools command passed')\n"];
            exit_code = 0;
            stdout.exact = "wasm-tools command passed\n";
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
            argv = ["@python@" "-c" "import subprocess, sys\nresult = subprocess.run(['@out@/bin/wasm-tools', '--aos-invalid-option'], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write('wasm-tools rejected invalid input\\n')\nraise SystemExit(7)\n"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "wasm-tools rejected invalid input\n";
          }
        ];
        artifacts = [];
      };
    };
    pname = "wasm-tools";
    inherit src;
    # Keep compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "wasm-tools-${version}-vendor";
      hash = "sha256-9/QqcFlC3DBKEaREmPUqMSDTVvgz/23tGo9NFJFJ8f0=";
    };
    cargoFlags = "-p wasm-tools --bin wasm-tools";

    # The upstream suite runs the full WebAssembly spec testsuite through every
    # subcommand and takes longer than the build itself. The install smoke
    # check below proves the binary loads and runs its argument parser.
    doCheck = false;

    postInstall = ''
      "$out/bin/wasm-tools" --version

      mkdir -p "$out/share/licenses/wasm-tools"
      cp LICENSE-APACHE LICENSE-Apache-2.0_WITH_LLVM-exception LICENSE-MIT \
        "$out/share/licenses/wasm-tools/"
    '';

    meta = {
      description = "Low-level tooling for WebAssembly modules and components";
      homepage = "https://github.com/bytecodealliance/wasm-tools";
      license = "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT";
      mainProgram = "wasm-tools";
    };
  }
