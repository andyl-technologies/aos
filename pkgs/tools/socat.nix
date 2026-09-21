##! socat — Multipurpose relay for bidirectional data transfer
{
  mkDerivation,
  fetchurl,
  gnumake,
  patch,
  patchelf,
  pkg-config,
  openssl,
  buildPackages,
}: let
  version = "1.8.1.3";
in
  mkDerivation {
    pname = "socat";
    inherit version;

    src = fetchurl {
      urls = [
        "http://www.dest-unreach.org/socat/download/socat-${version}.tar.bz2"
      ];
      hash = "sha256-JbxkdikrLmFCIJicd7C2/Kh7slJdl0ezGmY5sftgJBg=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [openssl];
    propagatedDeps = [];

    # Guard: keep the autotools build toolchain out of socat's
    # `-V`-baked PKG_CONFIG_PATH / CC strings.
    disallowedReferences = [
      buildPackages.gnumake
      buildPackages.pkg-config
      buildPackages.patch
      buildPackages.patchelf
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd socat-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          patch -p1 < ${./socat-openssl-4.patch}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-openssl \
            --with-openssl=${openssl}
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "socat — multipurpose relay for bidirectional data transfer";
      homepage = "http://www.dest-unreach.org/socat/";
      license = "GPL-2.0-only";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      rpath = testing.mkRPATHCheck {
        pkg = self;
        bins = ["socat"];
      };

      version = testing.mkToolCheck {
        pname = "tool-socat";
        tool = self;
        command = "socat -V";
      };
    };
  }
