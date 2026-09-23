##! XCB protocol descriptions and Python code-generation modules.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "1.17.0";
in
  mkDerivation {
    pname = "xcb-proto";
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/proto/xcb-proto-${version}.tar.xz"];
      hash = "130lc8jx43s83496nc8jn47zixjcp4abgsz69pvrjiqg279aq6rc";
    };
    buildDeps = [buildPackages.gnumake buildPackages.python3 buildPackages.libxml2];
    runtimeDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd xcb-proto-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          PYTHON=${buildPackages.python3}/bin/python3 $CONFIG_SHELL ./configure --prefix="$out"
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          make check
        '';
      }
      {
        name = "install";
        script = ''
          make install
          mkdir -p "$out/share/licenses/xcb-proto"
          mkdir -p "$out/lib/pkgconfig"
          ln -s "$out/share/pkgconfig/xcb-proto.pc" "$out/lib/pkgconfig/xcb-proto.pc"
          cp -r doc "$out/share/doc"
          cp COPYING "$out/share/licenses/xcb-proto/"
        '';
      }
    ];
    meta = {
      description = "XCB protocol descriptions and Python generator";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
