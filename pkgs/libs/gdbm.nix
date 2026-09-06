##! gdbm — GNU database manager
{
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
  readline,
}: let
  version = "1.26";
in
  mkDerivation {
    pname = "gdbm";
    inherit version;

    src = fetchurl {
      urls = ["https://ftp.gnu.org/gnu/gdbm/gdbm-${version}.tar.gz"];
      hash = "sha256-aiRQShTeSnRBA9y5Nr6Xbfb76IzP8mBl5UwcR5RvSl4=";
    };

    buildDeps = [gnumake gettext];
    runtimeDeps = [readline];
    propagatedDeps = [readline];
    configureFlags = builtins.concatStringsSep " " [
      "--enable-libgdbm-compat"
      "--enable-nls"
      "--enable-memory-mapped-io"
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-gdbm";
        library = self;
        libs = ["-lgdbm"];
        testSource = ''
          #include <gdbm.h>

          int main(void) {
              return gdbm_version == 0;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-gdbm";
        tool = self;
        command = "gdbmtool --version";
      };
    };

    meta = {
      description = "GNU library for extensible hash databases";
      homepage = "https://www.gnu.org/software/gdbm/";
      license = "GPL-3.0-or-later";
      mainProgram = "gdbmtool";
    };
  }
