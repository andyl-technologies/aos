##! kmod — Linux kernel module handling
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  openssl,
  zlib,
  xz,
  zstd,
}:
let
  version = "34";
in
mkDerivation {
  pname = "kmod";
  inherit version;

  src = fetchurl {
    urls = [
      "https://cdn.kernel.org/pub/linux/utils/kernel/kmod/kmod-${version}.tar.xz"
    ];
    hash = "sha256-EueIRIQVH71DK2pSAXDqGFwVn0OTx6LCqIarggMTFJo=";
  };

  buildDeps = [
    meson
    ninja
    pkg-config
  ];
  runtimeDeps = [
    openssl
    zlib
    xz
    zstd
  ];
  propagatedDeps = [
    openssl
    zlib
    xz
    zstd
  ];

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
        export PYTHONPATH="${meson}/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
        meson setup build \
          --prefix=$out \
          --sysconfdir=$out/etc \
          -Ddistconfdir=$out/lib \
          -Dzlib=enabled \
          -Dxz=enabled \
          -Dzstd=enabled \
          -Dmanpages=false \
          -Dbashcompletiondir=no
      '';
    }
    {
      name = "build";
      script = ''
        ninja -C build -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        export PYTHONPATH="${meson}/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
        ninja -C build install
      '';
    }
  ];

  meta = {
    description = "kmod — Linux kernel module handling tools";
    homepage = "https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git";
    license = "LGPL-2.1-or-later";
  };
}
