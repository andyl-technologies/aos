##! leangz — Lean build-artifact compressor and the leantar archive tool
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  pkg-config,
  zstd,
}: let
  # Lean 4 pins this leantar release for Lake's artifact cache archives.
  version = "0.1.20";
  src = fetchurl {
    urls = ["https://github.com/digama0/leangz/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-RrG3rqaQWs4vBggxQ73I54JkNRfGLRl1HYkzYg/USBY=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-nJZHOK0hRyyV1vqlQBU3YvOeLvRNWnitjnQf4DQprzM=";
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
    pname = "leangz";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "leantar reports its packaged release.";
        "files" = {};
        "input" = "No archive input.";
        "operation" = "Print the leantar version.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/leantar"
              "--version"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "leantar ${version}\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "leantar rejects a file that is not an ltar archive.";
        "files" = {
          "invalid.ltar" = "not an ltar archive\n";
        };
        "input" = "A text file named as an ltar archive.";
        "operation" = "Extract the malformed archive.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/leantar\", \"-x\", \"invalid.ltar\"], capture_output=True, text=True)\nassert result.returncode != 0, result\n\nsys.stderr.write(\"leantar rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "leantar rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    # The archive format is versioned independently; keep the exact release
    # Lean was qualified against.
    version = "=${version}";
    inherit src cargoDeps;

    buildDeps = [pkg-config];
    runtimeDeps = [zstd];

    # Link the AOS zstd library instead of the copy vendored in zstd-sys.
    cargoEnv = {
      ZSTD_SYS_USE_PKG_CONFIG = "1";
    };

    meta = {
      description = "Compression tools for Lean build artifacts, including leantar";
      homepage = "https://github.com/digama0/leangz";
      license = "Apache-2.0";
      mainProgram = "leantar";
    };
  }
