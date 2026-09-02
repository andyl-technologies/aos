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
}: let
  version = "34";
in
  mkDerivation {
    pname = "kmod";
    inherit version;

    src = fetchurl {
      urls = [
        # kernel.org retired /pub/linux/utils/kernel/kmod/ (kmod moved
        # to github.com/kmod-project, which publishes no dist tarball
        # assets); the whole directory 404s now. The cgit snapshot
        # service still serves per-tag archives (same source nixpkgs
        # uses), and kmod >= 33 is meson-native so the git tree builds
        # like the dist tarball.
        "https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git/snapshot/kmod-${version}.tar.gz"
      ];
      hash = "sha256-y0e+STZrWW5FVO7rdZWxKP6yYWGcdnVgPgBLB8XrvVs=";
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
          nativeMesonRoot=$(dirname "$(dirname "$(command -v meson)")")
          export PYTHONPATH="$nativeMesonRoot/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
          meson setup build \
            $mesonFlags \
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
          nativeMesonRoot=$(dirname "$(dirname "$(command -v meson)")")
          export PYTHONPATH="$nativeMesonRoot/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
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
