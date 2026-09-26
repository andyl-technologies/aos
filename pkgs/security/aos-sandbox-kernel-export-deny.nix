##! aos-sandbox-kernel-export-deny — scoped unique-mount-ID BPF-LSM experiment
{
  mkDerivation,
  stdenv,
  linux-headers,
  llvm,
  pkg-config,
  libbpf,
  buildPackages,
}: let
  targetArchBySystem = {
    "x86_64-linux" = "x86";
    "aarch64-linux" = "arm64";
  };
  targetArch =
    targetArchBySystem.${stdenv.system}
    or (throw "aos-sandbox-kernel-export-deny: unsupported system '${stdenv.system}'");
  bpfSource = ./aos-sandbox-kernel-export-deny.bpf.c;
  loaderSource = ./aos-sandbox-kernel-export-deny.c;
  abiHeader = ./aos-sandbox-kernel-export-deny.h;
in
  mkDerivation {
    pname = "aos-sandbox-kernel-export-deny";
    version = "2";
    src = null;

    buildDeps = [
      linux-headers
      llvm
      pkg-config
    ];
    runtimeDeps = [libbpf];
    propagatedDeps = [];
    disallowedReferences = [bpfSource loaderSource abiHeader];

    phases = [
      {
        name = "build";
        script = ''
          mkdir -p $out/bin $out/lib/bpf
          cp ${bpfSource} aos-sandbox-kernel-export-deny.bpf.c
          cp ${abiHeader} aos-sandbox-kernel-export-deny.h

          ${buildPackages.llvm}/bin/clang -target bpf -O2 -g \
            -D__TARGET_ARCH_${targetArch} \
            -I. \
            -I${linux-headers}/include \
            -I${libbpf}/include \
            -Wall -Wextra -Werror -Wno-unused-parameter \
            -c aos-sandbox-kernel-export-deny.bpf.c \
            -o $out/lib/bpf/aos-sandbox-kernel-export-deny.bpf.o
          ${buildPackages.llvm}/bin/llvm-strip -g \
            $out/lib/bpf/aos-sandbox-kernel-export-deny.bpf.o

          $CC -std=c17 -O2 -Wall -Wextra -Werror \
            -DAOS_KERNEL_EXPORT_DENY_OBJECT='"'$out/lib/bpf/aos-sandbox-kernel-export-deny.bpf.o'"' \
            -I. -I${linux-headers}/include \
            -o $out/bin/aos-sandbox-kernel-export-deny \
            ${loaderSource} \
            $(pkg-config --cflags --libs libbpf)
        '';
      }
    ];

    passthru.evidenceSources = [
      (builtins.path {
        path = ./aos-sandbox-kernel-export-deny.nix;
        name = "aos-sandbox-kernel-export-deny.nix";
      })
      (builtins.path {
        path = bpfSource;
        name = "aos-sandbox-kernel-export-deny.bpf.c";
      })
      (builtins.path {
        path = loaderSource;
        name = "aos-sandbox-kernel-export-deny.c";
      })
      (builtins.path {
        path = abiHeader;
        name = "aos-sandbox-kernel-export-deny.h";
      })
    ];

    checks = {
      self,
      pkgs,
      ...
    }: {
      validate = pkgs.runCommand "security-aos-sandbox-kernel-export-deny-validate" {} ''
        ${self}/bin/aos-sandbox-kernel-export-deny validate
        touch $out
      '';
    };

    meta = {
      description = "Default-deny BPF-LSM current-use gate for one export mount and cgroup";
      license = "Apache-2.0 AND (BSD-2-Clause OR GPL-2.0-only)";
    };
  }
