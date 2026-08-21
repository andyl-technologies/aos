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
}: let
  version = "1.14.1";
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
    pname = "firecracker";
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

    buildDeps = [
      llvm
      linux-headers
      cmake
      gnumake
    ];

    # bindgen needs libclang.so and system headers
    LIBCLANG_PATH = "${llvm}/lib";
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
