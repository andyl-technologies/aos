##! pkg-config — Helper tool for compiling applications and libraries
{
  mkDerivation,
  fetchurl,
  make,
}: let
  version = "0.29.2";
in
  mkDerivation {
    pname = "pkg-config";
    inherit version;

    src = fetchurl {
      urls = [
        "https://pkgconfig.freedesktop.org/releases/pkg-config-${version}.tar.gz"
      ];
      hash = "sha256-b8acAWiMlFilfrmhZkyaujcszaQgoCv0Qp/mEOfn1ZE=";
    };

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd pkg-config-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --with-internal-glib \
            --disable-host-tool
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

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "build-pkg-config";
        tool = self;
        command = "pkg-config --version";
      };

      query = testing.mkVMTest {
        name = "build-pkg-config-query";
        rootfsDeps = [
          self
          pkgs.zlib
        ];
        testScript = ''
          export PKG_CONFIG_PATH="${pkgs.zlib}/lib/pkgconfig"
          pkg-config --exists zlib
          echo "==> zlib found by pkg-config"
          pkg-config --cflags zlib
          echo "==> --cflags succeeded"
          pkg-config --libs zlib
          echo "==> --libs succeeded"
          echo "==> pkg-config-query passed"
        '';
      };

      compile = testing.mkVMTest {
        name = "build-pkg-config-compile";
        rootfsDeps = [
          self
          pkgs.zlib
          pkgs.make
        ];
        testScript = ''
          export PKG_CONFIG_PATH="${pkgs.zlib}/lib/pkgconfig"
          export C_INCLUDE_PATH="${pkgs.zlib}/include:$C_INCLUDE_PATH"
          export LIBRARY_PATH="${pkgs.zlib}/lib:$LIBRARY_PATH"
          export LD_LIBRARY_PATH="${pkgs.zlib}/lib:$LD_LIBRARY_PATH"

          cat > /tmp/ztest.c << 'EOF'
          #include <stdio.h>
          #include <zlib.h>
          int main() {
            printf("zlib version: %s\n", zlibVersion());
            return 0;
          }
          EOF

          CFLAGS=$(pkg-config --cflags zlib)
          LIBS=$(pkg-config --libs zlib)
          gcc $CFLAGS -o /tmp/ztest /tmp/ztest.c $LIBS
          /tmp/ztest
          echo "==> pkg-config-compile passed"
        '';
      };
    };

    meta = {
      description = "pkg-config — helper tool for compiling applications and libraries";
      homepage = "https://www.freedesktop.org/wiki/Software/pkg-config/";
      license = "GPL-2.0-or-later";
    };
  }
