##! rpcsvc-proto — RPC service protocol definitions and rpcgen
{
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
  buildPackages,
  stdenv,
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

    buildDeps =
      [
        gnumake
        gettext
      ]
      ++ (
        if stdenv.isCross
        then [buildPackages.rpcsvc-proto]
        else []
      );
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
            $configureFlags \
            --prefix=$out

          # rpcgen otherwise searches /lib/cpp and then PATH for a standalone
          # cpp binary. The AOS compiler is intentionally exposed through its
          # wrapper instead, so provide a build-local preprocessor launcher.
          build_cpp="$CC"
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            build_cpp="$CC_FOR_BUILD"
          fi
          mkdir -p build-tools
          cat > build-tools/cpp <<EOF
          #!$CONFIG_SHELL
          AOS_HARDENING_ENABLE= \
          C_INCLUDE_PATH= \
          CPLUS_INCLUDE_PATH= \
          LIBRARY_PATH= \
            exec "$build_cpp" -E "\$@"
          EOF
          chmod +x build-tools/cpp
          sed -i \
            's| -h -o| -Y $(top_builddir)/build-tools -h -o|' \
            rpcsvc/Makefile

          ${
            if stdenv.isCross
            then ''
              # rpcsvc header generation executes rpcgen during `make`.
              # Generate with the native tool while still building and
              # installing the complete Darwin rpcgen executable.
              sed -i \
                's|$(top_builddir)/rpcgen/rpcgen|${buildPackages.rpcsvc-proto}/bin/rpcgen|g' \
                rpcsvc/Makefile
            ''
            else ""
          }

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
