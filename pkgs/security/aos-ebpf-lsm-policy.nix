##! aos-ebpf-lsm-policy — Load fleet-managed BPF-LSM policy artifacts
{
  mkDerivation,
  stdenv,
  linux-headers,
  llvm,
  pkg-config,
  libbpf,
  json-c,
}: let
  targetArchBySystem = {
    "x86_64-linux" = "x86";
    "aarch64-linux" = "arm64";
  };
  targetArch =
    targetArchBySystem.${stdenv.system}
    or (throw "aos-ebpf-lsm-policy: unsupported system '${stdenv.system}'");
  bpfSource = ./aos-ebpf-lsm-policy.bpf.c;
  loaderSource = ./aos-ebpf-lsm-policy.c;
in
  mkDerivation {
    pname = "aos-ebpf-lsm-policy";
    version = "0";
    src = null;

    buildDeps = [
      linux-headers
      llvm
      pkg-config
    ];
    runtimeDeps = [
      libbpf
      json-c
    ];
    propagatedDeps = [];
    disallowedReferences = [bpfSource loaderSource];

    phases = [
      {
        name = "build";
        script = ''
          mkdir -p $out/bin $out/lib/bpf $out/share/aos/ebpf-lsm
          cp ${bpfSource} aos-ebpf-lsm-policy.bpf.c

          ${llvm}/bin/clang -target bpf -O2 -g \
            -D__TARGET_ARCH_${targetArch} \
            -I${linux-headers}/include \
            -I${libbpf}/include \
            -Wall -Wextra -Werror -Wno-unused-parameter \
            -c aos-ebpf-lsm-policy.bpf.c \
            -o $out/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o

          # clang -g emits BTF (for CO-RE) but also DWARF embedding the
          # kernel-headers path. Strip DWARF; .BTF is retained, CO-RE works.
          ${llvm}/bin/llvm-strip -g $out/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o

          $CC -O2 -Wall -Wextra -Werror \
            -I${linux-headers}/include \
            -o $out/bin/aos-ebpf-lsm-policy \
            ${loaderSource} \
            $(pkg-config --cflags --libs libbpf json-c)

          cat > $out/share/aos/ebpf-lsm/aos-task-audit.json <<'JSON'
          {
            "version": 1,
            "name": "aos-lsm-task-audit",
            "programs": ["aos_lsm_file_mprotect"]
          }
          JSON
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      validate = pkgs.runCommand "security-aos-ebpf-lsm-policy-validate" {} ''
        ${self}/bin/aos-ebpf-lsm-policy validate \
          --policy ${self}/share/aos/ebpf-lsm/aos-task-audit.json \
          --object ${self}/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o
        touch $out
      '';
    };

    meta = {
      description = "Load fleet-managed BPF-LSM policy artifacts";
      license = "MIT";
    };
  }
