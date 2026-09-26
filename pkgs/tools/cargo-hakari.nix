##! cargo-hakari — workspace-hack generator and validator.
{
  lib,
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
}: let
  version = "0.9.38";
  src = fetchurl {
    urls = [
      "https://github.com/guppy-rs/guppy/archive/refs/tags/cargo-hakari-${version}.tar.gz"
    ];
    hash = "sha256-vPLzO/vBEplbocL/PhxbEyIEuegr3KTxHL2XOkVWrGQ=";
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "cargo-hakari";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Cargo-hakari returns success and lists workspace-hack operations.";
        "files" = {};
        "input" = "The cargo-hakari command-line interface.";
        "operation" = "Request its offline help text.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/cargo-hakari\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"workspace-hack\" in result.stdout\nprint(\"cargo-hakari operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "cargo-hakari operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Cargo-hakari rejects the operation without reading a workspace.";
        "files" = {};
        "input" = "A cargo-hakari invocation naming an unknown operation.";
        "operation" = "Parse the unknown operation.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/cargo-hakari\", \"not-an-operation\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"cargo-hakari rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "cargo-hakari rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-+dnMXEeDrHptMrSGocLnLXsR1/eB16IYSGFBRTzsl4Y=";
    };
    cargoFlags = "-p cargo-hakari --bin cargo-hakari";
    doCheck = false;

    meta = {
      description = "Manage workspace-hack crates for faster Cargo builds";
      homepage = "https://docs.rs/cargo-hakari";
      license = "MIT OR Apache-2.0";
      mainProgram = "cargo-hakari";
    };
  }
