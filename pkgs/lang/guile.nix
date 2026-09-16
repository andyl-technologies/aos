##! guile — GNU extension language implementation
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  gawk,
  patch,
  gc,
  gmp,
  libffi,
  libtool,
  libunistring,
  libxcrypt,
  readline,
}: let
  version = "3.0.11";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "guile";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Guile prints the computed value.";
        "files" = {};
        "input" = "A Scheme expression mapping and summing a list.";
        "operation" = "Evaluate the expression with Guile.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/guile"
              "-c"
              "(display (apply + (map (lambda (x) (* x x)) '(1 2 3 4)))) (newline)"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "30\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Guile rejects the syntax error with status 1.";
        "files" = {};
        "input" = "A Scheme expression with an unterminated list.";
        "operation" = "Parse the malformed expression.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/guile"
              "-c"
              "(display (+ 1 2)"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://ftp.gnu.org/gnu/guile/guile-${version}.tar.xz"];
      hash = "sha256-gYx50jZlen+pb7NkE3zHtBs73uDWXGF0ygN2lVlXlGA=";
    };

    buildDeps = [gnumake pkg-config gawk patch];
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
          patch -p1 < ${./guile-patches/high-wakeup-fd.patch}

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
          # Thread wakeup pipes need two descriptors each. Let the suite use
          # the available descriptor budget without restricting its CPU set.
          ulimit -S -n "$(ulimit -H -n)"

          $CONFIG_SHELL ./libtool --mode=link "$CC" -I. \
            ${./guile-tests/high-wakeup-fd.c} libguile/libguile-3.0.la \
            -o high-wakeup-fd
          $CONFIG_SHELL ./meta/uninstalled-env ./high-wakeup-fd

          make -j"$NIX_BUILD_CORES" check
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
