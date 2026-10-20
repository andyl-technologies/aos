##! cargo-deny — lint a Cargo dependency graph for advisories, licenses, bans, and sources.
{
  lib,
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
}: let
  version = "0.20.2";
  src = fetchurl {
    urls = ["https://github.com/EmbarkStudios/cargo-deny/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-MfwdM/ro1bQmTbjtXGwHDCfNL4acxtKYOsA1SMWoHI4=";
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
            argv = ["@python@" "-c" "import subprocess\nresult = subprocess.run(['@out@/bin/cargo-deny', '--version'], capture_output=True, text=True)\nassert result.returncode == 0 and ('cargo-deny' in result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint('cargo-deny command passed')\n"];
            exit_code = 0;
            stdout.exact = "cargo-deny command passed\n";
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
            argv = ["@python@" "-c" "import subprocess, sys\nresult = subprocess.run(['@out@/bin/cargo-deny', '--aos-invalid-option'], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write('cargo-deny rejected invalid input\\n')\nraise SystemExit(7)\n"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "cargo-deny rejected invalid input\n";
          }
        ];
        artifacts = [];
      };
    };
    pname = "cargo-deny";
    inherit src;
    # Keep compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "cargo-deny-${version}-vendor";
      hash = "sha256-Zb6vQCnhhhL9Ducn9eh5P8Gfopl0lQPTXWW8Q0Y5xBQ=";
    };
    cargoFlags = "--bin cargo-deny";

    # The advisory and source tests fetch the RustSec database and Git
    # repositories, which the build sandbox forbids.
    doCheck = false;

    postInstall = ''
      "$out/bin/cargo-deny" --version

      mkdir -p "$out/share/licenses/cargo-deny"
      cp LICENSE-APACHE LICENSE-MIT "$out/share/licenses/cargo-deny/"
    '';

    meta = {
      description = "Cargo plugin for linting dependency advisories, licenses, bans, and sources";
      homepage = "https://embarkstudios.github.io/cargo-deny/";
      license = "MIT OR Apache-2.0";
      mainProgram = "cargo-deny";
    };
  }
