##! guile — GNU extension language implementation
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  gawk,
  patch,
  gc,
  gmp,
  libffi,
  libatomic_ops,
  libtool,
  libunistring,
  libxcrypt,
  readline,
  lib,
  stdenv,
  buildPackages,
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

    # Cross builds use the matching native Guile to compile Scheme sources.
    buildDeps =
      [gnumake pkg-config gawk patch]
      ++ lib.optionals (stdenv.isCross && stdenv.hostPlatform.isLinux) [buildPackages.guile];
    # Linux cross GC exposes libatomic_ops in its link interface. Guile
    # links it directly, so retain its runtime path through reference scrubbing.
    runtimeDeps =
      [gc gmp libffi libtool libunistring libxcrypt readline]
      ++ lib.optionals (stdenv.isCross && stdenv.hostPlatform.isLinux) [libatomic_ops];
    propagatedDeps =
      [gc gmp libffi libtool libunistring libxcrypt readline]
      ++ lib.optionals (stdenv.isCross && stdenv.hostPlatform.isLinux) [libatomic_ops];

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

          # The suspendable-port suite includes the ordinary port tests in a
          # separate process. Give each process its own files during make -j.
          patch -p1 < ${./guile-patches/parallel-port-fixtures.patch}

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
        script =
          lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # Build helpers select native Guile while cross-compiling. Runtime
            # checks must instead load the new target interpreter and bytecode.
            for helper in meta/guile meta/uninstalled-env meta/build-env; do
              cp "$helper" "$helper.for-build"
              sed -i 's/if test "yes" = "no"/if test "no" = "no"/g' "$helper"
            done
          ''
          + lib.optionalString (stdenv.isCross && stdenv.hostPlatform.system == "aarch64-linux") ''
            # QEMU user mode deliberately ignores memory resource limits.
            # The resource-limits package check runs these unchanged under a
            # target kernel; running them here allocates without bound.
            printf '\nTESTS := $(filter-out test-out-of-memory test-stack-overflow,$(TESTS))\n' \
              >> test-suite/standalone/Makefile

            # User-mode vfork becomes fork, losing glibc's shared spawn errno;
            # spawned native tools also report the build machine architecture.
            # Run the complete POSIX suite in the same target-kernel check.
            printf '\nTESTS := $(filter-out tests/posix.test,$(TESTS))\n' \
              >> test-suite/Makefile
          ''
          + ''
            # Thread wakeup pipes need two descriptors each. Let the suite use
            # the available descriptor budget without restricting its CPU set.
            ulimit -S -n "$(ulimit -H -n)"

            $CONFIG_SHELL ./libtool --mode=link "$CC" -I. \
              ${./guile-tests/high-wakeup-fd.c} libguile/libguile-3.0.la \
              -o high-wakeup-fd
            $CONFIG_SHELL ./meta/uninstalled-env ./high-wakeup-fd

            make -j"$NIX_BUILD_CORES" check
          ''
          + lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            for helper in meta/guile meta/uninstalled-env meta/build-env; do
              mv "$helper.for-build" "$helper"
            done
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
      pkgs,
      self,
      ...
    }:
      {
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
      }
      // lib.optionalAttrs (stdenv.hostPlatform.system == "aarch64-linux") {
        resource-limits = import ../../tests/build/guile-resource-limits.nix {
          inherit pkgs;
          guile = self;
        };
      };

    meta = {
      description = "Embeddable implementation of the Scheme programming language";
      homepage = "https://www.gnu.org/software/guile/";
      license = "LGPL-3.0-or-later";
      mainProgram = "guile";
    };
  }
