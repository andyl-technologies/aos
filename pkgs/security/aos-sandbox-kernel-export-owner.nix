##! aos-sandbox-kernel-export-owner — private two-phase BPF map custody experiment
{
  mkDerivation,
  stdenv,
  linux-headers,
  llvm,
  pkg-config,
  libbpf,
  openssl,
  buildPackages,
}: let
  targetArchBySystem = {
    "x86_64-linux" = "x86";
    "aarch64-linux" = "arm64";
  };
  targetArch =
    targetArchBySystem.${stdenv.system}
    or (throw "aos-sandbox-kernel-export-owner: unsupported system '${stdenv.system}'");
  bpfSource = ./aos-sandbox-kernel-export-deny.bpf.c;
  loaderSource = ./aos-sandbox-kernel-export-deny.c;
  ownerSource = ./aos-sandbox-kernel-export-owner.c;
  abiHeader = ./aos-sandbox-kernel-export-deny.h;
in
  mkDerivation {
    pname = "aos-sandbox-kernel-export-owner";
    version = "1";
    src = null;

    buildDeps = [linux-headers llvm pkg-config];
    runtimeDeps = [libbpf openssl];
    propagatedDeps = [];
    disallowedReferences = [bpfSource loaderSource ownerSource abiHeader];

    phases = [
      {
        name = "build";
        script = ''
          mkdir -p $out/bin $out/lib/bpf
          cp ${bpfSource} aos-sandbox-kernel-export-deny.bpf.c
          cp ${loaderSource} aos-sandbox-kernel-export-deny.c
          cp ${abiHeader} aos-sandbox-kernel-export-deny.h

          ${buildPackages.llvm}/bin/clang -target bpf -O2 -g \
            -DAOS_KERNEL_EXPORT_OWNER -D__TARGET_ARCH_${targetArch} \
            -I. -I${linux-headers}/include -I${libbpf}/include \
            -Wall -Wextra -Werror -Wno-unused-parameter \
            -c aos-sandbox-kernel-export-deny.bpf.c \
            -o $out/lib/bpf/aos-sandbox-kernel-export-owner.bpf.o
          ${buildPackages.llvm}/bin/llvm-strip -g \
            $out/lib/bpf/aos-sandbox-kernel-export-owner.bpf.o

          $CC -std=c17 -O2 -Wall -Wextra -Werror -Wno-unused-function \
            -DAOS_KERNEL_EXPORT_DENY_OBJECT='"'$out/lib/bpf/aos-sandbox-kernel-export-owner.bpf.o'"' \
            -I. -I${linux-headers}/include \
            -o $out/bin/aos-sandbox-kernel-export-owner \
            ${ownerSource} \
            $(pkg-config --cflags --libs libbpf openssl)
        '';
      }
    ];

    passthru.evidenceSources = [
      (builtins.path {
        path = ./aos-sandbox-kernel-export-owner.nix;
        name = "aos-sandbox-kernel-export-owner.nix";
      })
      (builtins.path {
        path = ownerSource;
        name = "aos-sandbox-kernel-export-owner.c";
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
      validate = pkgs.runCommand "security-aos-sandbox-kernel-export-owner-validate" {} ''
        ${self}/bin/aos-sandbox-kernel-export-owner validate
        touch $out
      '';
    };

    meta = {
      description = "Private staged BPF-LSM export grant owner experiment";
      license = "Apache-2.0 AND (BSD-2-Clause OR GPL-2.0-only)";
    };
  }
