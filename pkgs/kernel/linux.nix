# Linux Kernel
{
  mkDerivation,
  fetchurl,
  make,
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
}:

let
  version = "6.12.11";
in
mkDerivation {
  pname = "linux";
  inherit version;

  src = fetchurl {
    urls = [
      "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${version}.tar.xz"
    ];
    hash = "sha256-R1Fy/b2HoVPxI6V5Umcudzvbba9bWKQX0aXkGfz+7Ek=";
  };

  buildDeps = [
    make
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
  runtimeDeps = [ kmod ];
  propagatedDeps = [ ];

  # Path to kernel config fragments — these are merged before building.
  configDir = ./config;

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd linux-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        # Start with a default x86_64 config
        make defconfig ARCH=x86_64

        # Merge our config fragments on top
        for frag in $configDir/*.config; do
          scripts/kconfig/merge_config.sh -m .config "$frag"
        done

        # Finalize — fill in defaults for any new symbols
        make olddefconfig ARCH=x86_64
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES ARCH=x86_64 bzImage modules
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/boot $out/lib/modules

        # Install kernel image
        cp arch/x86/boot/bzImage $out/boot/vmlinuz-${version}
        cp System.map $out/boot/System.map-${version}
        cp .config $out/boot/config-${version}

        # Install modules
        make modules_install \
          INSTALL_MOD_PATH=$out \
          DEPMOD=${kmod}/sbin/depmod \
          ARCH=x86_64

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
