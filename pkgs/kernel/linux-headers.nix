##! Linux Headers — Kernel headers for userspace compilation
{
  lib,
  mkDerivation,
  linuxSource,
  stdenv,
  gnumake,
}: let
  archMap = {
    "x86_64-linux" = {karch = "x86_64";};
    "aarch64-linux" = {karch = "arm64";};
  };
  kernelArch =
    archMap.${stdenv.system}
    or (throw "linux-headers: unsupported system '${stdenv.system}'");
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "linux-headers";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The headers provide a self-consistent seccomp, audit, and socket-filter userspace ABI.";
        "files" = {
          "consumer.c" = "#include <linux/filter.h>\n#include <linux/seccomp.h>\n\n_Static_assert(SECCOMP_MODE_FILTER == 2, \"seccomp filter ABI changed\");\n_Static_assert(SECCOMP_RET_ALLOW == 0x7fff0000U, \"seccomp allow action changed\");\n_Static_assert(sizeof(struct seccomp_data) == 64, \"seccomp_data ABI size changed\");\n\nstatic struct sock_filter filter[] = {\n    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),\n    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_RET_ALLOW, 0, 1),\n    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),\n};\n\nint main(void) {\n    return filter[0].code == (BPF_LD | BPF_W | BPF_ABS) ? 0 : 1;\n}\n";
        };
        "input" = "A seccomp BPF consumer with compile-time checks for the published Linux UAPI layout and constants.";
        "operation" = "Compile the consumer using only the packaged sanitized kernel headers.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "-nostdinc"
              "-isystem"
              "@out@/include"
              "-Wall"
              "-Werror"
              "-c"
              "consumer.c"
              "-o"
              "consumer.o"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@python@"
              "-c"
              "data = open(\"consumer.o\", \"rb\").read(20)\nassert data[:4] == bytes([0x7f]) + b\"ELF\" and data[16:18] == bytes([1, 0])\nprint(\"linux-headers artifact passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "linux-headers artifact passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The C compiler rejects the incompatible structure-size assertion.";
        "files" = {
          "consumer.c" = "#include <linux/seccomp.h>\n_Static_assert(sizeof(struct seccomp_data) == 1, \"malformed seccomp ABI expectation\");\n";
        };
        "input" = "A consumer asserting a one-byte seccomp_data layout that contradicts the published UAPI.";
        "operation" = "Compile the malformed ABI expectation against the packaged sanitized headers.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "-nostdinc"
              "-isystem"
              "@out@/include"
              "-Wall"
              "-Werror"
              "-c"
              "consumer.c"
              "-o"
              "consumer.o"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit (linuxSource) version src;
    update = linuxSource.updateFor "linux-headers";

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd linux-${linuxSource.version}
        '';
      }
      {
        name = "install";
        script = ''
          # Use 'make headers' to sanitize headers in-tree, then copy manually.
          # This avoids 'make headers_install' which requires rsync, a tool not
          # present in the bootstrap toolchain.
          make headers ARCH=${kernelArch.karch}

          mkdir -p $out/include
          cp -r usr/include/* $out/include/

          # Remove extraneous files left by the kernel build system
          find $out/include -name '*.install.cmd' -delete
          find $out/include -name '..install.cmd' -delete
          find $out/include -name '.install' -delete
        '';
      }
    ];

    meta = {
      description = "Linux kernel headers for userspace compilation";
      homepage = "https://www.kernel.org";
      license = "GPL-2.0-only";
    };
  }
