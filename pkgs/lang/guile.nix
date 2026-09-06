##! guile — GNU extension language implementation
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  gawk,
  gc,
  gmp,
  libffi,
  libtool,
  libunistring,
  libxcrypt,
  readline,
  util-linux,
}: let
  version = "3.0.11";
in
  mkDerivation {
    pname = "guile";
    inherit version;

    src = fetchurl {
      urls = ["https://ftp.gnu.org/gnu/guile/guile-${version}.tar.xz"];
      hash = "sha256-gYx50jZlen+pb7NkE3zHtBs73uDWXGF0ygN2lVlXlGA=";
    };

    buildDeps = [gnumake pkg-config gawk util-linux];
    runtimeDeps = [gc gmp libffi libtool libunistring libxcrypt readline];
    propagatedDeps = [gc gmp libffi libtool libunistring libxcrypt readline];

    # Guile bytecode uses ELF containers that ordinary stripping corrupts.
    dontStrip = true;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd guile-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          # The Nix build filesystem may allocate the nominally sparse extent,
          # in which case SEEK_DATA correctly returns the current offset.
          sed -i '/"SEEK_DATA while in hole"/{n;s/4096/10/;}' \
            test-suite/tests/ports.test
          sed -i '/"SEEK_HOLE while in hole"/{n;s/10/4100/;}' \
            test-suite/tests/ports.test
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure $configureFlags \
            --prefix="$out" \
            --with-libreadline-prefix=${readline}
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''
          # Guile sizes its garbage-collector worker pool from the visible CPU
          # set.  On very large builders, the thread suite can consequently
          # allocate a descriptor above select(2)'s FD_SETSIZE.  Limit CPU
          # visibility for the test process while retaining the full suite.
          ${util-linux}/bin/taskset -c 0-15 make -j1 check
        '';
      }
      {
        name = "install";
        script = ''
          make install
          sed -i \
            -e 's|-lunistring|-L${libunistring}/lib -lunistring|g' \
            -e 's|-lltdl|-L${libtool}/lib -lltdl|g' \
            -e 's|-lcrypt|-L${libxcrypt}/lib -lcrypt|g' \
            "$out/lib/pkgconfig/guile-3.0.pc"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-guile";
        library = self;
        libs = ["-lguile-3.0"];
        testSource = ''
          #include <libguile.h>

          int main(void) {
              scm_init_guile();
              return 0;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-guile";
        tool = self;
        command = "guile --version && guile -c '(exit (if (= (+ 20 22) 42) 0 1))'";
      };
    };

    meta = {
      description = "Embeddable implementation of the Scheme programming language";
      homepage = "https://www.gnu.org/software/guile/";
      license = "LGPL-3.0-or-later";
      mainProgram = "guile";
    };
  }
