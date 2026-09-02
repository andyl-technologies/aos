##! aos-ebpf-net-policy — Attach package cgroup TCP network policies
{
  mkDerivation,
  stdenv,
  linux-headers,
  llvm,
  pkg-config,
  libbpf,
  json-c,
  buildPackages,
}: let
  targetArchBySystem = {
    "x86_64-linux" = "x86";
    "aarch64-linux" = "arm64";
  };
  targetArch =
    targetArchBySystem.${stdenv.system}
    or (throw "aos-ebpf-net-policy: unsupported system '${stdenv.system}'");
  bpfSource = ./aos-ebpf-net-policy.bpf.c;
  loaderSource = ./aos-ebpf-net-policy.c;
in
  mkDerivation {
    pname = "aos-ebpf-net-policy";
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
          mkdir -p $out/bin $out/lib/bpf
          cp ${bpfSource} aos-ebpf-net-policy.bpf.c

          ${buildPackages.llvm}/bin/clang -target bpf -O2 -g \
            -D__TARGET_ARCH_${targetArch} \
            -I${linux-headers}/include \
            -I${libbpf}/include \
            -Wall -Wextra -Werror \
            -c aos-ebpf-net-policy.bpf.c \
            -o $out/lib/bpf/aos-ebpf-net-policy.bpf.o

          # clang -g is required to emit BTF (for CO-RE), but it also writes
          # DWARF that embeds the kernel-headers include path, pinning
          # linux-headers into the runtime closure. Strip DWARF debug sections;
          # .BTF (not a debug section) is retained, so CO-RE still works.
          ${buildPackages.llvm}/bin/llvm-strip -g $out/lib/bpf/aos-ebpf-net-policy.bpf.o

          $CC -O2 -Wall -Wextra -Werror \
            -I${linux-headers}/include \
            -o $out/bin/aos-ebpf-net-policy \
            ${loaderSource} \
            $(pkg-config --cflags --libs libbpf json-c)
        '';
      }
    ];

    passthru.evidenceSources = [
      (builtins.path {
        path = ./aos-ebpf-net-policy.nix;
        name = "aos-ebpf-net-policy.nix";
      })
      (builtins.path {
        path = bpfSource;
        name = "aos-ebpf-net-policy.bpf.c";
      })
      (builtins.path {
        path = loaderSource;
        name = "aos-ebpf-net-policy.c";
      })
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: let
      samplePolicy = pkgs.writeTextFile {
        name = "aos-ebpf-net-policy-sample.json";
        # AOS's writeTextFile with no `destination` produces a *directory*
        # output (see pkgs/build-support/trivial-builders.nix); the JSON parser
        # needs a real file, so materialize the policy at a named path inside
        # the output and reference it explicitly below.
        destination = "/aos-ebpf-net-policy-sample.json";
        text = ''
          {
            "version": 1,
            "package": "sample",
            "mode": "private",
            "securityLabel": "aos-pkg-sample",
            "tcp": {
              "bind": [8000],
              "connect": [443]
            },
            "fs": {
              "readOnly": [],
              "readWrite": []
            },
            "landlock": {
              "abi": 4,
              "tcp": {
                "bind": [8000],
                "connect": [443]
              },
              "fs": {
                "readOnly": [],
                "readWrite": []
              }
            },
            "ebpf": {
              "identity": "aos-pkg-sample",
              "hooks": ["socket_bind", "socket_connect"],
              "tcp": {
                "bind": [8000],
                "connect": [443]
              }
            }
          }
        '';
      };
    in {
      validate = pkgs.runCommand "security-aos-ebpf-net-policy-validate" {} ''
        ${self}/bin/aos-ebpf-net-policy validate \
          --policy ${samplePolicy}/aos-ebpf-net-policy-sample.json \
          --object ${self}/lib/bpf/aos-ebpf-net-policy.bpf.o
        touch $out
      '';
    };

    meta = {
      description = "Attach package cgroup TCP network policies with eBPF";
      license = "MIT";
    };
  }
