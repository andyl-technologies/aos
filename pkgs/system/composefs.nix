##! composefs — Composite-filesystem builder (mkcomposefs)
##!
##! Builds the EROFS-formatted metadata image that AOS uses as the
##! bottom lower of the `/etc` overlay. The runtime mount is plain
##! `mount -t erofs ... -o ro,nodev,nosuid`; the `composefs.ko` /
##! `mount.composefs` runtime is not used. We therefore disable fuse
##! support and ship only the build-time tools (`mkcomposefs`,
##! `composefs-info`, `composefs-dump`).
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  openssl,
}: let
  version = "1.0.8";
in
  mkDerivation {
    pname = "composefs";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/composefs/composefs/releases/download/v${version}/composefs-${version}.tar.xz"
      ];
      hash = "sha256-IHOE3rGWGYrEdkxbQrtVj3xmFJQwKzgK/AlEdnhTg4Y=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
    ];
    runtimeDeps = [openssl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd composefs-${version}
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
            -Dfuse=disabled \
            -Dman=disabled
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
      description = "composefs — composite filesystem image builder";
      homepage = "https://github.com/composefs/composefs";
      # COPYING in the v1.0.8 release tarball:
      # `GPL-2.0-or-later OR Apache-2.0`. Parts derived from EROFS are
      # effectively `GPL-2.0-only OR Apache-2.0`; small `LGPL-2.1-or-later`
      # components live in libcomposefs.
      license = "GPL-2.0-or-later OR Apache-2.0";
    };
  }
