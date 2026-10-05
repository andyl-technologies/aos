##! Userspace kernel DRM interfaces and driver libraries
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  libpciaccess,
}: let
  version = "2.4.124";
in
  mkDerivation {
    pname = "libdrm";
    inherit version;

    src = fetchurl {
      urls = ["https://dri.freedesktop.org/libdrm/libdrm-${version}.tar.xz"];
      hash = "sha256-rDYpP2HKSq+vSxaip6//MSqk9cN8n715fenjwIY8o3k=";
    };

    buildDeps = [
      buildPackages.meson
      buildPackages.ninja
      buildPackages.pkg-config
      buildPackages.python3
      buildPackages.docutils
    ];
    runtimeDeps = [libpciaccess];
    propagatedDeps = [libpciaccess];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libdrm-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib \
              --buildtype=release -Dman-pages=enabled
          '';
        }
        {
          name = "build";
          script = ''
            PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages" \
              ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      # Compile the upstream tests for every target. Execution requires a
      # native package; DRM device tests cannot use an implicit host runner.
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages" \
              meson test -C build --print-errorlogs
          '';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
            PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages" \
              ninja -C build install
            mkdir -p "$out/share/licenses/libdrm"
            cp xf86drm.h xf86drmMode.h "$out/share/licenses/libdrm/"
          '';
        }
      ];

    meta = {
      description = "Userspace kernel DRM interfaces and driver libraries";
      homepage = "https://gitlab.freedesktop.org/mesa/drm";
      license = "MIT";
    };
  }
