# kmod — Linux kernel module handling
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  zlib,
  xz,
}:

let
  version = "33";
in
mkDerivation {
  pname = "kmod";
  inherit version;

  src = fetchurl {
    urls = [
      "https://mirrors.kernel.org/pub/linux/utils/kernel/kmod/kmod-${version}.tar.xz"
    ];
    hash = "sha256-3HaLMVUXIJH1bcaUMLVIHy127NnMtU6tjCVA289eqbw=";
  };

  buildDeps = [
    make
    pkg-config
  ];
  runtimeDeps = [
    zlib
    xz
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd kmod-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sysconfdir=/etc \
          --with-xz \
          --with-zlib \
          --with-zstd=no \
          --disable-manpages \
          --disable-test-modules
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        make install
        # Create compatibility symlinks
        mkdir -p $out/sbin
        for tool in depmod insmod lsmod modinfo modprobe rmmod; do
          ln -sf ../bin/kmod $out/sbin/$tool
        done
      '';
    }
  ];

  meta = {
    description = "kmod — Linux kernel module handling tools";
    homepage = "https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git";
    license = "LGPL-2.1-or-later";
  };
}
