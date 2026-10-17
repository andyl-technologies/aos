##! Source-built AArch64 Linux fixture for native gem5 full-system device checks
{
  mkDerivation,
  fetchurl,
  mkManualUpstream,
  buildPackages,
  llvm-gem5,
  gnumake,
  perl,
  bash,
  gawk,
  patch,
  openssl,
  bison,
  flex,
  elfutils,
  bc,
  dwarves,
  python3,
  zstd,
  kmod,
  rsync,
  coreutils,
}: let
  linuxSource = import ../kernel/_source.nix {inherit fetchurl mkManualUpstream;};
  hostInclude = "${buildPackages.elfutils}/include:${buildPackages.openssl}/include:${buildPackages.zlib}/include";
  hostLibrary = "${buildPackages.elfutils}/lib:${buildPackages.openssl}/lib:${buildPackages.zlib}/lib";
  hostCompiler = "env C_INCLUDE_PATH=${hostInclude} LIBRARY_PATH=${hostLibrary} ${buildPackages.cc}/bin/cc";
  # Linux queries an untargeted clang for GCC's include directory. Select the
  # source-built Clang intrinsic headers explicitly for AArch64 NEON units.
  kernelFlags = ''
    ARCH=arm64 LLVM=${llvm-gem5}/bin/ LLVM_IAS=1 KALLSYMS_EXTRA_PASS=1 \
    CC_FLAGS_FPU="-ffreestanding -isystem ${llvm-gem5}/lib/clang/22/include" \
    HOSTCC="${hostCompiler}" \
    HOSTCXX="env C_INCLUDE_PATH=${hostInclude} LIBRARY_PATH=${hostLibrary} ${buildPackages.cc}/bin/c++" \
    HOSTLD="${buildPackages.binutils}/bin/ld" HOSTAR="${buildPackages.binutils}/bin/ar" \
    HOSTPKG_CONFIG="${buildPackages.pkg-config}/bin/pkg-config" \
    CONFIG_SHELL=${bash}/bin/bash SHELL=${bash}/bin/bash \
    PYTHON3=${python3}/bin/python3 \
  '';
  sourceIdentity = builtins.toJSON {
    schema = "aos.linux.corresponding-source.v1";
    inherit (linuxSource) version;
    architecture = "aarch64";
    upstreamSource = "${linuxSource.src}";
    recipeSha256 = builtins.hashFile "sha256" ./gem5-aarch64-linux.nix;
    patches = [
      {
        file = "linux-gawk-array-argument.patch";
        sha256 = builtins.hashFile "sha256" ../kernel/linux-gawk-array-argument.patch;
      }
      {
        file = "linux-kallsyms-cortex-a53-veneer.patch";
        sha256 = builtins.hashFile "sha256" ./_gem5/linux-kallsyms-cortex-a53-veneer.patch;
      }
    ];
    tools = {
      llvm = "${llvm-gem5}";
      nativeCompiler = "${buildPackages.cc}";
      nativeBinutils = "${buildPackages.binutils}";
      make = "${gnumake}";
      shell = "${bash}";
      inherit perl gawk bison flex bc dwarves python3 zstd kmod rsync;
    };
  };
in
  mkDerivation {
    pname = "gem5-aarch64-linux";
    version = linuxSource.version;
    inherit (linuxSource) src;
    outputs = ["out" "source"];
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    buildDeps = [llvm-gem5 gnumake perl bash gawk patch openssl bison flex elfutils bc dwarves python3 zstd kmod rsync coreutils];
    runtimeDeps = [];
    hardeningDisable = ["all"];
    KBUILD_BUILD_TIMESTAMP = "1970-01-01";
    KBUILD_BUILD_USER = "aos";
    KBUILD_BUILD_HOST = "aos";
    KBUILD_BUILD_VERSION = "1";
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd linux-${linuxSource.version}
          patch --fuzz=0 -p1 < ${../kernel/linux-gawk-array-argument.patch}
          patch --fuzz=0 -p1 < ${./_gem5/linux-kallsyms-cortex-a53-veneer.patch}
        '';
      }
      {
        name = "configure";
        script = ''
          export LD_LIBRARY_PATH="${buildPackages.gcc-libs}/lib:${hostLibrary}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          make ${kernelFlags} defconfig
          # Preserve the architecture's ordinary feature set. Device paths used
          # by the initramfs must be built in rather than require a guest loader.
          ${bash}/bin/bash scripts/config \
            --enable ARCH_VEXPRESS --enable ARM_GIC --enable ARM_GIC_V3 \
            --enable ARM_ARCH_TIMER --enable OF --enable BLK_DEV_INITRD \
            --enable DEVTMPFS --enable DEVTMPFS_MOUNT --enable PROC_FS --enable SYSFS \
            --enable SERIAL_AMBA_PL011 --enable SERIAL_AMBA_PL011_CONSOLE \
            --enable VIRTIO --enable VIRTIO_MMIO --enable VIRTIO_BLK \
            --enable VIRTIO_NET --enable VIRTIO_CONSOLE \
            --enable NET --enable PACKET --enable NET_9P --enable NET_9P_VIRTIO \
            --enable 9P_FS --enable 9P_FS_POSIX_ACL
          make ${kernelFlags} olddefconfig
          for symbol in ARCH_VEXPRESS ARM_GIC ARM_GIC_V3 ARM_ARCH_TIMER OF \
            BLK_DEV_INITRD DEVTMPFS SERIAL_AMBA_PL011 SERIAL_AMBA_PL011_CONSOLE \
            VIRTIO VIRTIO_MMIO VIRTIO_BLK VIRTIO_NET PACKET NET_9P NET_9P_VIRTIO 9P_FS; do
            grep -qx "CONFIG_$symbol=y" .config
          done
        '';
      }
      {
        name = "build";
        script = ''
          export LD_LIBRARY_PATH="${buildPackages.gcc-libs}/lib:${hostLibrary}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          make -j"$NIX_BUILD_CORES" ${kernelFlags} Image modules
        '';
      }
      {
        name = "install";
        script = ''
          export LD_LIBRARY_PATH="${buildPackages.gcc-libs}/lib:${hostLibrary}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          mkdir -p "$out/boot" "$out/share/licenses/linux"
          cp arch/arm64/boot/Image "$out/boot/Image"
          cp vmlinux System.map .config "$out/boot/"
          cp COPYING "$out/share/licenses/linux/"
          make ${kernelFlags} INSTALL_HDR_PATH="$out" headers_install
          make ${kernelFlags} INSTALL_MOD_PATH="$out" DEPMOD=${kmod}/sbin/depmod modules_install

          # Co-retain the exact complete upstream source, ordered changes,
          # build recipe and realized configuration with every binary root.
          # Sources remain independent of the temporary object build tree.
          mkdir -p "$source/patches" "$source/build" "$source/licenses"
          cp "$src" "$source/linux-upstream.tar.xz"
          cp ${../kernel/linux-gawk-array-argument.patch} "$source/patches/linux-gawk-array-argument.patch"
          cp ${./_gem5/linux-kallsyms-cortex-a53-veneer.patch} "$source/patches/linux-kallsyms-cortex-a53-veneer.patch"
          cp ${./gem5-aarch64-linux.nix} "$source/build/recipe.nix"
          cp ${../kernel/_source.nix} "$source/build/kernel-source.nix"
          cp ${./_gem5/aarch64-artifact-check.py} "$source/build/aarch64-artifact-check.py"
          cp .config "$source/build/config"
          cp COPYING "$source/licenses/"
          cp -R LICENSES "$source/licenses/"
          cat > "$source/source-manifest.json" <<'EOF'
          ${sourceIdentity}
          EOF
          (cd "$out/boot"; ${coreutils}/bin/sha256sum Image vmlinux System.map .config) \
            > "$source/binary-bindings.sha256"
          ln -s "$source" "$out/share/corresponding-source"
        '';
      }
      {
        name = "check";
        script = ''
          ${python3}/bin/python3 ${./_gem5/aarch64-artifact-check.py} kernel "$out"
          ${python3}/bin/python3 ${./_gem5/aarch64-artifact-check.py} source "$source" "$out"
        '';
      }
    ];
    meta.description = "Cross-builds a stock AArch64 Linux kernel with built-in gem5 VExpress/GIC/timer/modern VirtIO paths; does not qualify simulator behavior";
    meta.license = "GPL-2.0-only";
  }
