##! Khronos GL, EGL and GLES headers distributed by libglvnd
{
  mkDerivation,
  fetchurl,
}: let
  version = "1.7.0";
in
  mkDerivation {
    pname = "libglvnd-headers";
    inherit version;

    src = fetchurl {
      urls = ["https://gitlab.freedesktop.org/glvnd/libglvnd/-/archive/v${version}/libglvnd-v${version}.tar.gz"];
      hash = "sha256-K24VsGqvtMC24jSBJICMvZspHGRymeqrouMgL1H/Lz0=";
    };

    buildDeps = [];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libglvnd-v${version}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/include" "$out/share/licenses/libglvnd-headers"
          # Public directories installed by upstream include/meson.build.
          for api in GL EGL GLES GLES2 GLES3 KHR glvnd; do
            cp -R "include/$api" "$out/include/"
          done
          # The release has per-file notices rather than a root COPYING.
          cp include/GL/gl.h include/EGL/eglplatform.h include/KHR/khrplatform.h \
            include/glvnd/GLdispatchABI.h "$out/share/licenses/libglvnd-headers/"
        '';
      }
    ];

    meta = {
      description = "Khronos GL, EGL and GLES API headers from libglvnd";
      homepage = "https://gitlab.freedesktop.org/glvnd/libglvnd";
      license = "MIT AND Apache-2.0";
    };
  }
