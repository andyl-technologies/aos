##! wac — compose WebAssembly components with the WAC language.
{
  lib,
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
}: let
  version = "0.11.0";
  src = fetchurl {
    urls = ["https://github.com/bytecodealliance/wac/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-iZnmxA2I61eGQk+hUN8cDl8mqykiO4i8xvvTakovPJc=";
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
            argv = ["@python@" "-c" "import subprocess\nresult = subprocess.run(['@out@/bin/wac', '--version'], capture_output=True, text=True)\nassert result.returncode == 0 and ('wac' in result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint('wac-cli command passed')\n"];
            exit_code = 0;
            stdout.exact = "wac-cli command passed\n";
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
            argv = ["@python@" "-c" "import subprocess, sys\nresult = subprocess.run(['@out@/bin/wac', '--aos-invalid-option'], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write('wac-cli rejected invalid input\\n')\nraise SystemExit(7)\n"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "wac-cli rejected invalid input\n";
          }
        ];
        artifacts = [];
      };
    };
    pname = "wac-cli";
    inherit src;
    # Keep compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "wac-cli-${version}-vendor";
      hash = "sha256-seLmdg6p644E/XqyCqTGjufMuXkR9PBtoEvjrp664Go=";
    };
    cargoFlags = "-p wac-cli --bin wac";

    # Registry-backed tests reach a package registry over the network, which
    # the build sandbox forbids.
    doCheck = false;

    postInstall = ''
      "$out/bin/wac" --version

      mkdir -p "$out/share/licenses/wac-cli"
      cp LICENSE "$out/share/licenses/wac-cli/"
    '';

    meta = {
      description = "Compose WebAssembly components with the WebAssembly Compositions language";
      homepage = "https://github.com/bytecodealliance/wac";
      license = "Apache-2.0 WITH LLVM-exception";
      mainProgram = "wac";
    };
  }
