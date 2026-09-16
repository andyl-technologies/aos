##! Bazel 7 — build tool
{
  mkDerivation,
  mkManualUpstream,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
  bash,
  coreutils,
  which,
  zip,
  unzip,
  gawk,
  python3,
  openjdk-21,
  gcc,
  binutils,
  grep,
  gzip,
  patch,
  diffutils,
  findutils,
  sed,
  tar,
  xz,
  file,
  patchelf,
  bazel-bootstrap,
  bootstrapTools,
  gcc-libs,
  llvm,
}: let
  upstream = mkManualUpstream {
    unitId = "bazel-7";
    family = "bazel";
    stream = "7";
    owner = "pkgs/toolchain/bazel-7.nix";
    member = "bazel-7";
    version = "7.7.1";
    reason = "Bazel source and repository dependencies form one curated artifact graph that requires maintainer review.";
    successorUnit = "bazel-8";
  };
  mkBazel = import ./_bazel.nix {
    inherit
      mkDerivation
      fetchurl
      lib
      stdenv
      buildPackages
      bash
      coreutils
      which
      zip
      unzip
      gawk
      python3
      openjdk-21
      gcc
      binutils
      grep
      gzip
      patch
      diffutils
      findutils
      sed
      tar
      xz
      file
      patchelf
      bazel-bootstrap
      bootstrapTools
      gcc-libs
      llvm
      ;
  };
in
  mkBazel {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "Bazel returns success and reports its release version.";
      "files" = {};
      "input" = "The packaged Bazel launcher and embedded release identity.";
      "operation" = "Request the launcher version without loading a workspace.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess\nresult = subprocess.run([\"@out@/bin/bazel\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"bazel\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"bazel-7 operation passed\")\n"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "bazel-7 operation passed\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "Bazel rejects the unsupported startup option.";
      "files" = {};
      "input" = "A Bazel startup request containing an unknown option.";
      "operation" = "Parse the invalid startup option before loading a workspace.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/bazel\", \"--aos-invalid-startup-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"bazel-7 rejected invalid input\\n\")\nraise SystemExit(7)\n"
          ];
          "exit_code" = 7;
          "observes_rejection" = true;
          "stderr" = {
            "exact" = "bazel-7 rejected invalid input\n";
          };
          "stdout" = {
            "exact" = "";
          };
        }
      ];
    };
  };

    inherit (upstream) version update;
    srcHash = "sha256-YYGzVwwvZX2YmxFB+wwaCOtfCBBspXfcfcUufQI4N5o=";
    vendorDepsHash = "sha256-UIedT89X6y12snR54HGoZyLuFaHupcSDxu9ZibkzYeA=";
  }
