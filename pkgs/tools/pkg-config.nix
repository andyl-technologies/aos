##! pkg-config — Helper tool for compiling applications and libraries
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "0.29.2";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  crossConfigureCache =
    if stdenv.isCross
    then ''
      # Bundled GLib discovers stack direction by executing a target binary.
      # Every AOS target supported by this package uses a downward-growing
      # stack, so provide the result explicitly during cross compilation.
      export ac_cv_c_stack_direction=-1
      export glib_cv_stack_grows=no

      # These bundled GLib probes also execute target programs. Both glibc and
      # Darwin provide overlap-safe bcopy and the POSIX passwd/group APIs.
      export glib_cv_working_bcopy=yes
      export ac_cv_func_posix_getpwuid_r=yes
      export ac_cv_func_nonposix_getpwuid_r=no
      export ac_cv_func_posix_getgrgid_r=yes
      export ac_cv_func_nonposix_getgrgid_r=no

      # ELF C symbols have no leading underscore; Mach-O symbols do.
      export glib_cv_uscore=${
        if stdenv.hostPlatform.isDarwin
        then "yes"
        else "no"
      }
    ''
    else "";
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

    buildDeps = [gnumake];
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
        script =
          if isDarwinCross
          then ''
            ${crossConfigureCache}

            # Bundled GLib 2.38 detects Carbon by preprocessing its umbrella
            # header. The AOS compiler SDK deliberately exposes the surviving
            # header-only compatibility surface, but no linkable Carbon
            # framework, so that probe is a false positive. Keep pkg-config's
            # private GLib on its complete Unix collation and XDG-directory
            # implementations instead of selecting code that cannot compile or
            # link against the target platform. Patch the pregenerated script;
            # touching configure.ac would spuriously require an unavailable
            # historical Automake version during this release-tarball build.
            test "$(grep -c '^  glib_have_carbon=yes$' glib/configure)" -eq 1
            sed -i 's/^  glib_have_carbon=yes$/  glib_have_carbon=no/' \
              glib/configure
            test "$(grep -c '^  glib_have_carbon=no$' glib/configure)" -eq 1

            # Bundled GLib discovers this by executing a target binary.
            # Both supported Darwin architectures use downward-growing stacks.
            # pkg-config 0.29 embeds GLib 2.38, whose atomic pointer macros
            # intentionally pass integer-sized masks through GCC builtins.
            # Modern Clang diagnoses that historical extension as an error.
            export CFLAGS="''${CFLAGS:-} -Wno-int-conversion"

            ./configure \
              $configureFlags \
              --prefix=$out \
              --with-internal-glib \
              --disable-host-tool
          ''
          else ''
            ${crossConfigureCache}

            ./configure \
              $configureFlags \
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
          pkgs.gnumake
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

      pkg-config-chain = testing.mkVMTest {
        name = "cross-cutting-pkg-config-chain";
        rootfsDeps = [
          self
          pkgs.openssl
        ];
        testScript = ''
          export PKG_CONFIG_PATH="${pkgs.openssl}/lib/pkgconfig:$PKG_CONFIG_PATH"
          export C_INCLUDE_PATH="${pkgs.openssl}/include:$C_INCLUDE_PATH"
          export LIBRARY_PATH="${pkgs.openssl}/lib:$LIBRARY_PATH"
          export LD_LIBRARY_PATH="${pkgs.openssl}/lib:$LD_LIBRARY_PATH"

          echo "==> Querying pkg-config for openssl"
          pkg-config --modversion openssl
          echo "    CFLAGS: $(pkg-config --cflags openssl)"
          echo "    LIBS:   $(pkg-config --libs openssl)"

          cat > /tmp/pkgtest.c << 'EOF'
          #include <openssl/crypto.h>
          #include <stdio.h>
          int main(void) {
              printf("OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
              return 0;
          }
          EOF

          echo "==> Compiling with pkg-config-discovered flags"
          gcc -o /tmp/pkgtest /tmp/pkgtest.c $(pkg-config --cflags --libs openssl)
          echo "==> Running"
          /tmp/pkgtest
          echo "pkg-config chain: PASS"
        '';
      };
    };

    meta = {
      description = "pkg-config — helper tool for compiling applications and libraries";
      homepage = "https://www.freedesktop.org/wiki/Software/pkg-config/";
      license = "GPL-2.0-or-later";
    };
  }
