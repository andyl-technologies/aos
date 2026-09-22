##! libexif — EXIF metadata reader and writer used by image processing libraries.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "0.6.26";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libexif";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/libexif/libexif/releases/download/v${version}/libexif-${version}.tar.xz"];
      hash = "sha256-SgVe1ldeYcpGwxcr48dTzBbJvs0Pmexx1Y3Q5HFHbAw=";
    };

    buildDeps = [buildPackages.gnumake buildPackages.gettext buildPackages.pkg-config];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libexif-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out"
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES"
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
              make check
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make install
            mkdir -p "$out/share/licenses/libexif"
            cp COPYING "$out/share/licenses/libexif/"
          '';
        }
      ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libexif";
        library = self;
        libs = ["-lexif"];
        testSource = ''
          #include <stddef.h>
          #include <libexif/exif-data.h>

          int main(void) {
              ExifData *data = exif_data_new();
              if (data == NULL) return 1;
              exif_data_unref(data);
              return 0;
          }
        '';
      };
    };

    meta = {
      description = "Library for parsing and writing EXIF image metadata";
      homepage = "https://libexif.github.io/";
      license = "LGPL-2.1-or-later";
    };
  }
