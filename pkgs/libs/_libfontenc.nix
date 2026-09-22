##! X font encoding library; a data-free build bootstraps the encoding indexer.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  xorgproto,
  zlib,
  encodings ? null,
}: let
  version = "1.1.9";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libfontenc";
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libfontenc-${version}.tar.xz"];
      hash = "1qkky8647gmv2qcy07444r76cgxbrcvd49qxzvah625ibiq950wx";
    };
    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.pkg-config];
    runtimeDeps =
      [xorgproto zlib]
      ++ (
        if encodings == null
        then []
        else [encodings]
      );
    propagatedDeps = [xorgproto zlib];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libfontenc-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release -Ddefault_library=both \
              -Dwith-encodingsdir=${
              if encodings == null
              then "$out/share/fonts/X11/encodings"
              else "${encodings}/share/fonts/X11/encodings"
            }
          '';
        }
        {
          name = "build";
          script = ''
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages ninja -C build
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages meson test -C build --print-errorlogs
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            meson install -C build
            mkdir -p "$out/share/licenses/libfontenc"
            cp COPYING "$out/share/licenses/libfontenc/"
          '';
        }
      ];
    meta = {
      description = "X font encoding library";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
