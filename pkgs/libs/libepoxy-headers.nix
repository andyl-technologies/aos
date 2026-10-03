##! Public OpenGL, EGL and GLX headers generated from Epoxy's Khronos registries
{
  mkDerivation,
  buildPackages,
  fetchurl,
  libglvnd-headers,
  libx11,
}: let
  version = "1.5.10";
in
  mkDerivation {
    pname = "libepoxy-headers";
    inherit version;
    src = fetchurl {
      urls = ["https://download.gnome.org/sources/libepoxy/1.5/libepoxy-${version}.tar.xz"];
      hash = "sha256-ByzaS1ndCYu6jCNjpiRymdsfqJQR3CIci4G47oGS5iM=";
    };

    buildDeps = [buildPackages.python3];
    runtimeDeps = [libglvnd-headers libx11];
    propagatedDeps = [libglvnd-headers libx11];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libepoxy-${version}
        '';
      }
      {
        name = "generate";
        script = ''
          mkdir -p generated/epoxy
          # These are the same registry and command arguments as Epoxy's
          # Meson public-header targets. No library or dispatch stub is emitted.
          for api in gl egl glx; do
            ${buildPackages.python3}/bin/python3 src/gen_dispatch.py \
              --header --no-source --outputdir=generated/epoxy "registry/$api.xml"
            cp "include/epoxy/$api.h" generated/epoxy/
          done
          cp include/epoxy/common.h generated/epoxy/
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/include" "$out/share/licenses/libepoxy-headers"
          cp -R generated/epoxy "$out/include/"
          cp COPYING "$out/share/licenses/libepoxy-headers/"
        '';
      }
    ];

    meta = {
      description = "Generated public OpenGL, EGL and GLX API headers from libepoxy";
      homepage = "https://github.com/anholt/libepoxy";
      license = "MIT";
    };
  }
