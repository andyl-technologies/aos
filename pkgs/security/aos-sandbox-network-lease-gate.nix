##! aos-sandbox-network-lease-gate — Fixed tc-BPF ownership-lease packet gate
{
  mkDerivation,
  stdenv,
  linux-headers,
  llvm,
  libbpf,
  buildPackages,
}: let
  targetArchBySystem = {
    "x86_64-linux" = "x86";
    "aarch64-linux" = "arm64";
  };
  targetArch =
    targetArchBySystem.${stdenv.system}
    or (throw "aos-sandbox-network-lease-gate: unsupported system '${stdenv.system}'");
  bpfSource = ./aos-sandbox-network-lease-gate.bpf.c;
  abiHeader = ./aos-sandbox-network-lease-gate.h;
in
  mkDerivation {
    pname = "aos-sandbox-network-lease-gate";
    version = "1";
    src = null;

    buildDeps = [
      linux-headers
      llvm
      libbpf
    ];
    runtimeDeps = [];
    propagatedDeps = [];
    disallowedReferences = [bpfSource abiHeader];

    phases = [
      {
        name = "build";
        script = ''
          mkdir -p $out/include/aos $out/lib/bpf
          cp ${abiHeader} aos-sandbox-network-lease-gate.h
          cp ${bpfSource} aos-sandbox-network-lease-gate.bpf.c

          ${buildPackages.llvm}/bin/clang -target bpf -O2 -g \
            -D__TARGET_ARCH_${targetArch} \
            -I. \
            -I${linux-headers}/include \
            -I${libbpf}/include \
            -Wall -Wextra -Werror \
            -c aos-sandbox-network-lease-gate.bpf.c \
            -o $out/lib/bpf/aos-sandbox-network-lease-gate.bpf.o

          # Keep BTF for map/program inspection while removing source paths
          # carried only by DWARF debug sections.
          ${buildPackages.llvm}/bin/llvm-strip -g \
            $out/lib/bpf/aos-sandbox-network-lease-gate.bpf.o

          cp aos-sandbox-network-lease-gate.h \
            $out/include/aos/sandbox-network-lease-gate.h
        '';
      }
    ];

    passthru.evidenceSources = [
      (builtins.path {
        path = ./aos-sandbox-network-lease-gate.nix;
        name = "aos-sandbox-network-lease-gate.nix";
      })
      (builtins.path {
        path = bpfSource;
        name = "aos-sandbox-network-lease-gate.bpf.c";
      })
      (builtins.path {
        path = abiHeader;
        name = "aos-sandbox-network-lease-gate.h";
      })
    ];

    meta = {
      description = "Fixed tc-BPF sandbox ownership-lease packet gate";
      license = "Apache-2.0";
    };
  }
