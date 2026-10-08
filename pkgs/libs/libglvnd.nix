##! Vendor-neutral OpenGL, GLX, EGL, and GLES dispatch libraries
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  libx11,
  libxext,
  xorgproto,
}: let
  version = "1.7.0";
in
  mkDerivation {
    pname = "libglvnd";
    inherit version;

    src = fetchurl {
      urls = ["https://gitlab.freedesktop.org/glvnd/libglvnd/-/archive/v${version}/libglvnd-v${version}.tar.gz"];
      hash = "sha256-K24VsGqvtMC24jSBJICMvZspHGRymeqrouMgL1H/Lz0=";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.pkg-config buildPackages.python3];
    runtimeDeps = [libx11 libxext xorgproto];
    propagatedDeps = [libx11 libxext xorgproto];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libglvnd-v${version}
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib \
              --buildtype=release -Dx11=enabled -Dglx=enabled
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
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            # GLX test executables require a running X server. They remain
            # built and belong to the separate display integration check.
            PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages" \
              meson test -C build --print-errorlogs --no-suite glx
          '';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
            PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages" \
              ninja -C build install
            mkdir -p "$out/share/licenses/libglvnd"
            cp include/GL/gl.h include/EGL/eglplatform.h include/KHR/khrplatform.h \
              include/glvnd/GLdispatchABI.h "$out/share/licenses/libglvnd/"
            cp src/util/cJSON/LICENSE "$out/share/licenses/libglvnd/cJSON-LICENSE"
            cp src/util/uthash/LICENSE "$out/share/licenses/libglvnd/uthash-LICENSE"
          '';
        }
      ];

    meta = {
      description = "Vendor-neutral OpenGL, GLX, EGL, and GLES dispatch libraries";
      homepage = "https://gitlab.freedesktop.org/glvnd/libglvnd";
      license = "MIT AND Apache-2.0 AND BSD-1-Clause";
    };
  }
