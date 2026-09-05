##! libmetalink — Metalink XML document parser
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  file,
  expat,
}: let
  version = "0.1.3";
in
  mkDerivation {
    pname = "libmetalink";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/metalink-dev/libmetalink/releases/download/release-${version}/libmetalink-${version}.tar.bz2"
      ];
      hash = "sha256-B1OuEVLZcNw78yfQzlz+/sovGrEylLEV5kgRFjpo/U8=";
    };

    buildDeps = [gnumake pkg-config file];
    runtimeDeps = [expat];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libmetalink-${version}
          sed -i "s|/usr/bin/file|${file}/bin/file|g" configure
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --disable-static \
            --without-libxml2 \
            --with-libexpat
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''make -j"$NIX_BUILD_CORES" check'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libmetalink";
        library = self;
        libs = ["-lmetalink"];
        testSource = ''
          #include <metalink/metalink.h>

          int main(void) {
              metalink_t *document = NULL;
              metalink_delete(document);
              return 0;
          }
        '';
      };
    };

    meta = {
      description = "C library for parsing Metalink XML documents";
      homepage = "https://github.com/metalink-dev/libmetalink";
      license = "MIT";
    };
  }
