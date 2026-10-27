##! Source-built BPF inspection, object linking and skeleton generation.
{
  lib,
  mkDerivation,
  linuxSource,
  linux,
  stdenv,
  buildPackages,
  gnumake,
  pkg-config,
  python3,
  llvm,
  elfutils,
  zlib,
  zstd,
  openssl,
  libcap,
}: let
  # The native metadata reader and target disassembler must describe one release.
  nativeLlvm = assert buildPackages.llvm.version == llvm.version; buildPackages.llvm;
  kernelBuild = "${linux.dev}/lib/modules/${linuxSource.version}/build";
  hostIncludes = "${buildPackages.elfutils}/include:${buildPackages.openssl}/include:${buildPackages.zlib}/include:${buildPackages.zstd}/include";
  hostLibraries = "${buildPackages.elfutils}/lib:${buildPackages.openssl}/lib:${buildPackages.zlib}/lib:${buildPackages.zstd}/lib";
in
  mkDerivation {
    pname = "bpftool";
    # Track the exact kernel source release; `bpftool version` separately
    # reports the tool and its private libbpf versions from that source.
    version = "=${linuxSource.version}";
    inherit (linuxSource) src;
    update = linuxSource.updateFor "bpftool";

    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A compiler-generated BTF object containing a named two-field structure.";
        operation = "Decode the object's BTF with the installed bpftool and inspect its JSON type layout.";
        expected = "The named structure has its exact size and member bit offsets.";
        files."probe.c" = ''
          struct aos_bpf_probe {
              unsigned int key;
              unsigned long long value;
          };
          struct aos_bpf_probe probe;
        '';
        artifacts = [];
        steps = [
          {
            argv = ["@cc@" "-gbtf" "-c" "probe.c" "-o" "probe.o"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                import json, subprocess
                result = subprocess.check_output([
                    "@out@/bin/bpftool", "-j", "btf", "dump", "file", "probe.o", "format", "raw"
                ])
                records = json.loads(result)["types"]
                record, = [item for item in records if item.get("name") == "aos_bpf_probe"]
                assert record["kind"] == "STRUCT" and record["size"] == 16, record
                assert [(member["name"], member["bits_offset"]) for member in record["members"]] == [
                    ("key", 0), ("value", 64)
                ], record
                print("bpftool BTF layout passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "bpftool BTF layout passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Bytes that do not encode an ELF or raw BTF object.";
        operation = "Attempt to decode malformed BTF input with the installed bpftool.";
        expected = "The decoder refuses the input and emits no type data.";
        files."bad.o" = "not an ELF object\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/bpftool" "btf" "dump" "file" "bad.o" "format" "raw"];
            exit_code = 95;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = ''
              libbpf: failed to get EHDR from bad.o
              Error: failed to load BTF from bad.o: Unknown error 4001
            '';
          }
        ];
      };
    };

    buildDeps = [gnumake pkg-config python3 llvm (toString linux.dev)];
    runtimeDeps = [elfutils zlib zstd openssl libcap llvm];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd linux-${linuxSource.version}
          sed -i '1c\#!${buildPackages.python3}/bin/python3' scripts/bpf_doc.py
          cd tools/bpf/bpftool
        '';
      }
      {
        name = "build";
        script = ''
          aos_llvm_config=llvm-config
          ${lib.optionalString stdenv.isCross ''
            # The target llvm-config cannot execute on the build machine.
            # Translate the matching native tool's metadata and reject any
            # other build-side store dependency instead of linking it silently.
            mkdir -p .aos-native-tools
            cat > .aos-native-tools/llvm-config <<'LLVM_CONFIG_WRAPPER'
            #!${buildPackages.bash}/bin/bash
            set -euo pipefail

            native_output=$('${nativeLlvm}/bin/llvm-config' "$@")
            target_output=$(printf '%s\n' "$native_output" |
              sed 's|${nativeLlvm}|${llvm}|g')

            for store_root in $(printf '%s\n' "$target_output" |
              grep -oE '/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+' || true); do
              if [ "$store_root" != '${llvm}' ]; then
                echo "bpftool: llvm-config exposed an unmapped build-side path: $store_root" >&2
                exit 1
              fi
            done
            printf '%s\n' "$target_output"
            LLVM_CONFIG_WRAPPER
            chmod +x .aos-native-tools/llvm-config
            aos_llvm_config="$PWD/.aos-native-tools/llvm-config"
          ''}

          # Pin BTF to the AOS target kernel. Never probe the builder's /sys or
          # /boot; the same source also builds bpftool's private bootstrap libbpf.
          make -j$NIX_BUILD_CORES \
            SHELL="$CONFIG_SHELL" \
            CC="$CC" AR="$AR" LD="$LD" \
            HOSTCC="env C_INCLUDE_PATH=${hostIncludes} LIBRARY_PATH=${hostLibraries} ${buildPackages.cc}/bin/cc" \
            HOSTAR="${buildPackages.binutils}/bin/ar" \
            HOSTLD="${buildPackages.binutils}/bin/ld" \
            CLANG="${nativeLlvm}/bin/clang" \
            LLVM_CONFIG="$aos_llvm_config" \
            LLVM_STRIP="${nativeLlvm}/bin/llvm-strip" \
            ARCH=${stdenv.hostPlatform.linuxArch} \
            VMLINUX_BTF="${kernelBuild}/vmlinux"

          # Missing optional dependencies must not silently remove features
          # needed by the manager or the ordinary inspection/signing commands.
          grep -Eq '^feature-clang-bpf-co-re[[:space:]]*=[[:space:]]*1$' FEATURE-DUMP.bpftool
          grep -Eq '^feature-llvm[[:space:]]*=[[:space:]]*1$' FEATURE-DUMP.bpftool
          grep -Eq '^feature-libcap[[:space:]]*=[[:space:]]*1$' FEATURE-DUMP.bpftool
          test -s profiler.skel.h
          test -s pid_iter.skel.h
          ${lib.optionalString (!stdenv.isCross) ''
            ./bpftool version
            ./bpftool gen skeleton profiler.bpf.o > generated-profiler.h
            grep -Fq 'struct profiler_bpf' generated-profiler.h
          ''}
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm755 bpftool "$out/bin/bpftool"
          install -Dm644 bash-completion/bpftool \
            "$out/share/bash-completion/completions/bpftool"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      rpath = testing.mkRPATHCheck {
        pkg = self;
        bins = ["bpftool"];
      };
      dynamic-linker = testing.mkDynLinkerCheck {
        pkg = self;
        bins = ["bpftool"];
      };
    };

    meta = {
      description = "Linux BPF inspection, signing, object linking and skeleton generation";
      homepage = "https://github.com/libbpf/bpftool";
      license = "GPL-2.0-only OR BSD-2-Clause";
      mainProgram = "bpftool";
    };
  }
