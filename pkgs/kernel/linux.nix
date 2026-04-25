##! Linux Kernel
{
  mkDerivation,
  linuxSource,
  stdenv,
  gnumake,
  perl,
  bash,
  gawk,
  openssl,
  kmod,
  bison,
  flex,
  rsync,
  elfutils,
  bc,
  binutils,
  gcc-libs,
  # Optional: extra kernel config fragment text to merge after the base
  # config fragments. Like NixOS structuredExtraConfig but as raw kconfig text.
  extraConfig ? "",
}: let
  archMap = {
    "x86_64-linux" = {
      karch = "x86_64";
      target = "bzImage";
      imgPath = "arch/x86/boot/bzImage";
    };
    "aarch64-linux" = {
      karch = "arm64";
      target = "Image";
      imgPath = "arch/arm64/boot/Image";
    };
  };
  kernelArch =
    archMap.${stdenv.system}
    or (throw "linux: unsupported system '${stdenv.system}'");
in
  mkDerivation {
    pname = "linux";
    inherit (linuxSource) version src;

    buildDeps = [
      gnumake
      perl
      bash
      gawk
      openssl
      bison
      flex
      rsync
      elfutils
      bc
      binutils
    ];
    runtimeDeps = [kmod];
    propagatedDeps = [];

    # Path to kernel config fragments — these are merged before building.
    configDir = ./config;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd linux-${linuxSource.version}
        '';
      }
      {
        name = "configure";
        script = ''
          # Start with a default config for the target architecture
          make defconfig ARCH=${kernelArch.karch}

          # Merge our config fragments on top
          for frag in $configDir/*.config; do
            scripts/kconfig/merge_config.sh -m .config "$frag"
          done

          # Merge extra config from the system profile
          ${
            if extraConfig != ""
            then ''
              cat > .extra-config << 'EXTRAEOF'
              ${extraConfig}
              EXTRAEOF
              scripts/kconfig/merge_config.sh -m .config .extra-config
            ''
            else ""
          }

          # Finalize — fill in defaults for any new symbols
          make olddefconfig ARCH=${kernelArch.karch}
        '';
      }
      {
        name = "build";
        script = ''
          # sorttable (host tool) uses pthreads; glibc's pthread_exit needs
          # libgcc_s.so.1 for stack unwinding at runtime.
          export LD_LIBRARY_PATH="${gcc-libs}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          make -j$NIX_BUILD_CORES ARCH=${kernelArch.karch} ${kernelArch.target} modules
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/boot $out/lib/modules

          # Install kernel image
          cp ${kernelArch.imgPath} $out/boot/vmlinuz-${linuxSource.version}
          cp vmlinux $out/boot/vmlinux-${linuxSource.version}
          cp System.map $out/boot/System.map-${linuxSource.version}
          cp .config $out/boot/config-${linuxSource.version}

          # Install modules
          make modules_install \
            INSTALL_MOD_PATH=$out \
            DEPMOD=${kmod}/sbin/depmod \
            ARCH=${kernelArch.karch}

          # Remove build/source symlinks (they point to the build dir)
          rm -f $out/lib/modules/*/build $out/lib/modules/*/source
        '';
      }
    ];

    meta = {
      description = "Linux kernel — the operating system kernel";
      homepage = "https://www.kernel.org";
      license = "GPL-2.0-only";
    };
  }
