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
  buildPackages,
  openssl,
}: let
  version = "1.0.8";
  opensslLibraryPath = "${openssl}/lib";
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
      buildPackages.patchelf
    ];
    runtimeDeps = [openssl];
    propagatedDeps = [];

    # Meson rewrites installed targets to their declared install RPATH, which
    # is empty in this release. Restore the declared OpenSSL path on the
    # library that directly needs libcrypto; the standard fixup still prunes
    # entries that do not satisfy a DT_NEEDED dependency.
    postInstall = ''
      library="$out/lib/libcomposefs.so.1.4.0"
      test -f "$library"
      ${buildPackages.patchelf}/bin/patchelf --print-needed "$library" \
        | grep -qx 'libcrypto.so.3'
      ${buildPackages.patchelf}/bin/patchelf \
        --add-rpath "${opensslLibraryPath}" "$library"
    '';

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
