##! Wasmtime — standalone WebAssembly and component-model runtime CLI.
{
  lib,
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
}: let
  version = "49.0.1";

  # The release source archive carries the Git submodules that the GitHub
  # tag archive omits; several workspace members build from them.
  src = fetchurl {
    urls = ["https://github.com/bytecodealliance/wasmtime/releases/download/v${version}/wasmtime-v${version}-src.tar.gz"];
    hash = "sha256-FH7vKERjCCqFQTjilN9c1IrvRu49m2ta243kghJzd8M=";
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
            argv = ["@python@" "-c" "import subprocess\nresult = subprocess.run(['@out@/bin/wasmtime', '--version'], capture_output=True, text=True)\nassert result.returncode == 0 and ('wasmtime' in result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint('wasmtime command passed')\n"];
            exit_code = 0;
            stdout.exact = "wasmtime command passed\n";
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
            argv = ["@python@" "-c" "import subprocess, sys\nresult = subprocess.run(['@out@/bin/wasmtime', '--aos-invalid-option'], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write('wasmtime rejected invalid input\\n')\nraise SystemExit(7)\n"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "wasmtime rejected invalid input\n";
          }
        ];
        artifacts = [];
      };
    };
    pname = "wasmtime";
    inherit src;
    # Keep compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "wasmtime-${version}-vendor";
      hash = "sha256-Iq8apl1MNynlKjFUakJ4J5zStoJPfex+qImh1ky2HWE=";
    };
    cargoFlags = "-p wasmtime-cli --bin wasmtime";

    # The upstream suite compiles guest programs for WASI targets that the AOS
    # Rust toolchain does not ship. The install smoke check below proves the
    # runtime loads and runs its argument parser.
    doCheck = false;

    postInstall = ''
      "$out/bin/wasmtime" --version

      mkdir -p "$out/share/licenses/wasmtime"
      cp LICENSE "$out/share/licenses/wasmtime/"
    '';

    meta = {
      description = "Fast and secure runtime for WebAssembly modules and components";
      homepage = "https://wasmtime.dev";
      license = "Apache-2.0 WITH LLVM-exception";
      mainProgram = "wasmtime";
    };
  }
