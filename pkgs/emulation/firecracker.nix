##! Firecracker — lightweight VMM for serverless workloads
{
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
  lib,
  libseccomp,
  llvm,
  linux-headers,
  cmake,
  gnumake,
  bootstrapTools,
  glibc,
  stdenv,
  buildPackages,
}: let
  version = "1.14.1";
  isLinuxCross = stdenv.isCross && stdenv.hostPlatform.isLinux;
  buildLlvm =
    if isLinuxCross
    then buildPackages.llvm
    else llvm;
  buildTargetPrefix = lib.toUpper (builtins.replaceStrings ["-"] ["_"] stdenv.buildPlatform.config);

  # Firecracker's build script compiles seccomp policies on the build machine.
  # Its seccompiler dependency must link and load native libseccomp while the
  # final binary continues to use the target library.
  buildLinker = buildPackages.writeShellScriptBin "firecracker-build-cc" ''
    unset AOS_CROSS_COMPILING AOS_GOARCH AOS_GOOS
    unset AOS_HARDENING_DISABLE AOS_HARDENING_ENABLE
    unset AOS_OBJECT_FORMAT AOS_RUST_TARGET AOS_TARGET_ARCH AOS_TARGET_PLATFORM
    unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH
    unset MACOSX_DEPLOYMENT_TARGET SDKROOT
    unset NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS
    exec ${buildPackages.cc}/bin/cc \
      -L${buildPackages.libseccomp}/lib \
      -Wl,-rpath,${buildPackages.libseccomp}/lib "$@"
  '';

  src = fetchurl {
    urls = [
      "https://github.com/firecracker-microvm/firecracker/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-Z4gROwvYO1L2RDkMl4J7/UJYxdhK4/79/ICu79rWEm8=";
  };
  microHttpGitDeps = [
    {
      url = "https://github.com/firecracker-microvm/micro-http";
      rev = "5c2254d6cf4f32a668d0d8e57ba20bebad9d4fba";
      crate = "micro_http";
      sourceArchive = fetchurl {
        urls = [
          "https://github.com/firecracker-microvm/micro-http/archive/5c2254d6cf4f32a668d0d8e57ba20bebad9d4fba.tar.gz"
        ];
        hash = "sha256-YD8yYrSgQ1/gnwFhw98+89aYgpOfltFMWQh2AeD1znA=";
      };
    }
  ];
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "firecracker";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Firecracker returns success and reports its version.";
        "files" = {};
        "input" = "The packaged Firecracker monitor's release identity.";
        "operation" = "Request its version without creating a virtual machine.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/firecracker\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"Firecracker\" in (result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint(\"firecracker operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "firecracker operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Firecracker rejects the unsupported option.";
        "files" = {};
        "input" = "A Firecracker invocation containing an unknown option.";
        "operation" = "Parse the invalid option before opening the API socket.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/firecracker\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"firecracker rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "firecracker rejected invalid input\n";
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
      # Firecracker has a Git dependency on micro_http. Its fixed-output archive
      # lets restricted evaluators create a normal fetch derivation.
      gitDeps = microHttpGitDeps;
      hash = "sha256-eGkw6H4DB42osPimndIch63k9vQyA4d5h8ylV1Ptau4=";
    };

    # Pass gitDeps so cargo build config also replaces the git source
    gitDeps = microHttpGitDeps;

    buildDeps =
      [llvm]
      # Splicing Linux headers as a build dependency selects native syscall
      # numbers. Cross compilation uses the target sysroot and bindgen flags.
      ++ lib.optionals (!isLinuxCross) [linux-headers]
      ++ [cmake gnumake]
      ++ lib.optionals isLinuxCross [buildPackages.libseccomp];

    cargoEnv = lib.optionalAttrs isLinuxCross {
      "CARGO_TARGET_${buildTargetPrefix}_LINKER" = "${buildLinker}/bin/firecracker-build-cc";
    };

    # bindgen needs libclang.so and system headers
    LIBCLANG_PATH = "${buildLlvm}/lib";
    BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${glibc.dev}/include -isystem ${linux-headers}/include";

    # Build only the firecracker binary from the workspace
    cargoFlags = "-p firecracker";
    doCheck = false;

    runtimeDeps = [libseccomp];

    meta = {
      description = "Firecracker — lightweight virtual machine monitor for serverless workloads";
      homepage = "https://github.com/firecracker-microvm/firecracker";
      license = "Apache-2.0";
    };
  }
