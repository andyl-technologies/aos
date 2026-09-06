##! lksctp-tools — Linux SCTP userspace library and tools
{
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  libtool,
  m4,
}: let
  version = "1.0.21";
in
  mkDerivation {
    pname = "lksctp-tools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/sctp/lksctp-tools/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-hzi/F+z/u+JECm4v+vHLzrtjP8mdY9iHYa81wCpXGJM=";
    };

    buildDeps = [gnumake autoconf automake libtool m4];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd lksctp-tools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export ACLOCAL_PATH="${libtool}/share/aclocal''${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
          autoreconf -fi
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-shared \
            --enable-static
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
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
        pname = "lib-sctp";
        library = self;
        libs = ["-lsctp"];
        testSource = ''
          #include <netinet/sctp.h>

          int main(void) {
              return sctp_getaddrlen(AF_INET) > 0 ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "Linux SCTP userspace library and tools";
      homepage = "https://github.com/sctp/lksctp-tools";
      license = "LGPL-2.1-only AND GPL-2.0-or-later";
    };
  }
