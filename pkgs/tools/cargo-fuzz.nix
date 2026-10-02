##! cargo-fuzz — drive libFuzzer targets from Cargo.
{
  lib,
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
}: let
  version = "0.13.2";
  src = fetchurl {
    urls = ["https://github.com/rust-fuzz/cargo-fuzz/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-iOF5gF5P5MmQNyCgBO9pA7DyiyeiLnRmDNcvWGEva0Y=";
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
            argv = ["@python@" "-c" "import subprocess\nresult = subprocess.run(['@out@/bin/cargo-fuzz', '--version'], capture_output=True, text=True)\nassert result.returncode == 0 and ('cargo-fuzz' in result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint('cargo-fuzz command passed')\n"];
            exit_code = 0;
            stdout.exact = "cargo-fuzz command passed\n";
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
            argv = ["@python@" "-c" "import subprocess, sys\nresult = subprocess.run(['@out@/bin/cargo-fuzz', '--aos-invalid-option'], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write('cargo-fuzz rejected invalid input\\n')\nraise SystemExit(7)\n"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "cargo-fuzz rejected invalid input\n";
          }
        ];
        artifacts = [];
      };
    };
    pname = "cargo-fuzz";
    inherit src;
    # Keep compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "cargo-fuzz-${version}-vendor";
      hash = "sha256-7P3bii0Y0hf3z9RCPIH6uClFIw/CTtUSzbTbaZNQkYQ=";
    };
    cargoFlags = "--bin cargo-fuzz";

    # The integration tests create and build fuzz projects, which downloads
    # crates and requires a nightly compiler for sanitizer flags.
    doCheck = false;

    postInstall = ''
      "$out/bin/cargo-fuzz" --version

      mkdir -p "$out/share/licenses/cargo-fuzz"
      cp LICENSE-APACHE LICENSE-MIT "$out/share/licenses/cargo-fuzz/"
    '';

    meta = {
      description = "Command-line helper for fuzzing Rust code with libFuzzer";
      homepage = "https://github.com/rust-fuzz/cargo-fuzz";
      license = "MIT OR Apache-2.0";
      mainProgram = "cargo-fuzz";
    };
  }
