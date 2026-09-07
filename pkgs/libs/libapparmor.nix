##! libapparmor — AppArmor policy interaction library
{
  mkDerivation,
  fetchurl,
  autoconf,
  autoconf-archive,
  automake,
  libtool,
  gnumake,
  pkg-config,
  flex,
  bison,
  swig,
  perl,
  python3,
  setuptools,
  ncurses,
  libxcrypt,
}: let
  version = "4.1.7";
in
  mkDerivation {
    pname = "libapparmor";
    inherit version;
    src = fetchurl {
      urls = ["https://gitlab.com/apparmor/apparmor/-/archive/v${version}/apparmor-v${version}.tar.gz"];
      hash = "sha256-3tTNQZuKBQAqEIoJEiCOIJhpV1JmTGpZRk0t2kGOBFI=";
    };
    buildDeps = [
      autoconf
      autoconf-archive
      automake
      libtool
      gnumake
      pkg-config
      flex
      bison
      swig
      perl
      python3
      setuptools
      ncurses
    ];
    runtimeDeps = [perl python3 libxcrypt];
    propagatedDeps = [libxcrypt];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd apparmor-v${version}/libraries/libapparmor
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i 's/install_vendor/install_site/' swig/perl/Makefile.am
        '';
      }
      {
        name = "configure";
        script = ''
          export ACLOCAL_PATH="${autoconf-archive}/share/aclocal:${libtool}/share/aclocal:${pkg-config}/share/aclocal"
          export PYTHONPATH=${setuptools}/lib/python3.14/site-packages
          autoreconf -fiv
          ./configure $configureFlags \
            --prefix="$out" \
            --with-perl \
            --with-python
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''
          # The legacy parser harness requires Expect, which does not support
          # Tcl 9. Build its test executable and validate the language bindings
          # after installation instead.
          make -C testsuite test_multi.multi
        '';
      }
      {
        name = "install";
        script = ''
          make install
          test -f "$out/lib/libapparmor.so"
          python_path=$(find "$out" -type d -name site-packages -print -quit)
          test -n "$python_path"
          PYTHONPATH="$python_path" ${python3}/bin/python3 -c 'import LibAppArmor'
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-libapparmor";
        library = self;
        libs = ["-lapparmor"];
        testSource = ''
          #include <sys/apparmor.h>
          int main(void) {
            return aa_is_enabled() < 0;
          }
        '';
      };
    };
    meta = {
      description = "Library for querying and changing AppArmor confinement";
      homepage = "https://apparmor.net/";
      license = "LGPL-2.1-only AND GPL-2.0-only";
    };
  }
