##! Check — Unit testing framework for C
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
}: let
  version = "0.15.2";
in
  mkDerivation {
    pname = "check";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/libcheck/check/releases/download/${version}/check-${version}.tar.gz"];
      hash = "sha256-qN5OC6z7TXbdHGGN7SY1I7U7hdkqFG2INesaUpMvogo=";
    };
    buildDeps = [gnumake pkg-config];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd check-${version}
        '';
      }
      {
        name = "configure";
        script = ''./configure $configureFlags --prefix="$out"'';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install
          test -x "$out/bin/checkmk"
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-check";
        library = self;
        libs = ["-lcheck"];
        testSource = ''
          #include <check.h>
          int main(void) {
            Suite *suite = suite_create("aos");
            return suite == 0;
          }
        '';
      };
    };
    meta = {
      description = "Provides a unit testing framework for C";
      homepage = "https://libcheck.github.io/check/";
      license = "LGPL-2.1-or-later";
      mainProgram = "checkmk";
    };
  }
