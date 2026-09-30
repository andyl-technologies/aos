##! Userspace kernel DRM interfaces and driver libraries
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  python3,
  docutils,
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

    buildDeps = [meson ninja pkg-config python3 docutils];
    runtimeDeps = [libpciaccess];
    propagatedDeps = [libpciaccess];

    phases = [
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
          PYTHONPATH="${meson}/lib/python3/site-packages" \
            ninja -C build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH="${meson}/lib/python3/site-packages" \
            meson test -C build --print-errorlogs
        '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH="${meson}/lib/python3/site-packages" \
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
