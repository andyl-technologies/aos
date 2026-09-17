##! gdbm — GNU database manager
{
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
  patch,
  lib,
  readline,
  ncurses,
  stdenv,
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

    buildDeps = [gnumake gettext] ++ lib.optionals stdenv.hostPlatform.isLinux [patch];

    # Strict flexible-array checks reject the lexer's one-element tail buffers.
    # Patch both the lexer input and its generated C without weakening hardening.
    patches = lib.optionals stdenv.hostPlatform.isLinux [./gdbm-patches/flexible-lexer-buffers.patch];

    # Linux gdbmtool links ncurses directly in addition to readline.
    runtimeDeps = [readline] ++ lib.optionals stdenv.hostPlatform.isLinux [ncurses];
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

      tool-store = testing.mkToolCheck {
        pname = "tool-gdbm-store";
        tool = self;
        command = ''
          gdbmtool -N -n /tmp/tool.gdbm store 'key with spaces' 'value with spaces' &&
          gdbmtool -N -r /tmp/tool.gdbm fetch 'key with spaces'
        '';
        expectedOutput = "value with spaces";
      };
    };

    meta = {
      description = "GNU library for extensible hash databases";
      homepage = "https://www.gnu.org/software/gdbm/";
      license = "GPL-3.0-or-later";
      mainProgram = "gdbmtool";
    };
  }
