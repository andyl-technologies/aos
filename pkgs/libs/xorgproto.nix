##! X11 protocol headers, specifications, and key-symbol definitions.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "2025.1";
in
  mkDerivation {
    pname = "xorgproto";
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/proto/xorgproto-${version}.tar.xz"];
      hash = "1s38fskf23wnh4d3i104biq7g0jjbhz9r3425n5dyy05diqqr2an";
    };
    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.python3-libevdev];
    runtimeDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd xorgproto-${version}
          sed -i '1s|^#!.*|#!${buildPackages.python3}/bin/python3|' scripts/keysym-generator.py
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release
        '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages ninja -C build
        '';
      }
      {
        name = "check";
        script = ''
          # The native key-symbol verifier checks architecture-independent headers.
          PYTHONPATH=${buildPackages.python3-libevdev}/lib/python3.14/site-packages:${buildPackages.meson}/lib/python3/site-packages \
            ${buildPackages.python3}/bin/python3 -m mesonbuild.mesonmain test -C build --print-errorlogs
        '';
      }
      {
        name = "install";
        script = ''
          meson install -C build
          mkdir -p "$out/share/licenses/xorgproto" "$out/lib/pkgconfig"
          cp COPYING-* "$out/share/licenses/xorgproto/"
          for metadata in "$out/share/pkgconfig/"*.pc; do
            ln -s "../../share/pkgconfig/$(basename "$metadata")" "$out/lib/pkgconfig/$(basename "$metadata")"
          done
        '';
      }
    ];
    meta = {
      description = "X11 protocol headers and specifications";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
