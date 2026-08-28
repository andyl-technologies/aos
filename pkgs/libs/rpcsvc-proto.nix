##! rpcsvc-proto — RPC service protocol definitions and rpcgen
{
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
  gcc,
}: let
  version = "1.4.4";
in
  mkDerivation {
    pname = "rpcsvc-proto";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/thkukuk/rpcsvc-proto/releases/download/v${version}/rpcsvc-proto-${version}.tar.xz"
      ];
      hash = "sha256-gcOqJ+212KGO8CcIHruYQjTVtYYMZb2Z1KyPAxRaVYs=";
    };

    buildDeps = [
      gnumake
      gettext
      gcc
    ];
    runtimeDeps = [gettext];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd rpcsvc-proto-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out

          grep '^USE_NLS = yes$' Makefile
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
      description = "RPC service protocol definitions and rpcgen compiler";
      homepage = "https://github.com/thkukuk/rpcsvc-proto";
      license = "BSD-3-Clause";
    };

    checks = {
      testing,
      self,
      ...
    }: {
      rpcgen = testing.mkToolCheck {
        pname = "tool-rpcgen";
        tool = self;
        command = "rpcgen --help";
      };

      catalogs = testing.mkVMTest {
        name = "lib-rpcsvc-proto-nls";
        rootfsDeps = [self];
        testScript = ''
          test -d ${self}/share/locale
          find ${self}/share/locale -type f -name '*.mo' | grep .
        '';
      };
    };
  }
