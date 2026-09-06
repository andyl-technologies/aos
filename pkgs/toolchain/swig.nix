##! SWIG — Interface compiler for connecting native code to other languages
{
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  libtool,
  bison,
  gnumake,
  pcre2,
  perl,
  python3,
  tcl,
}: let
  version = "4.4.1";
in
  mkDerivation {
    pname = "swig";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/swig/swig/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-i/MgQr637h7rXHGqFaYlE9lkiT+EI08s135Kji7UHoc=";
    };
    buildDeps = [autoconf automake libtool bison gnumake perl python3 tcl];
    runtimeDeps = [pcre2];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd swig-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          # CCache's optional manual requires Yodl, while all interface
          # compiler functionality and the main SWIG manual remain available.
          sed -i '/man1/d' CCache/Makefile.in
          sed -i "1s|^#!.*|#!$CONFIG_SHELL|" autogen.sh
        '';
      }
      {
        name = "configure";
        script = ''
          ./autogen.sh
          ./configure $configureFlags --prefix="$out"
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install
          "$out/bin/swig" -version | grep -q 'SWIG Version ${version}'
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-swig";
        tool = self;
        command = "swig -version | grep -q 'SWIG Version ${version}'";
      };
    };
    meta = {
      description = "Connects C and C++ code to high-level programming languages";
      homepage = "https://www.swig.org/";
      license = "GPL-3.0-or-later";
      mainProgram = "swig";
    };
  }
