##! inetutils — GNU network utility suite
{
  mkDerivation,
  fetchurl,
  gnumake,
  ncurses,
  libxcrypt,
  perl,
}: let
  version = "2.8";
in
  mkDerivation {
    pname = "inetutils";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftpmirror.gnu.org/gnu/inetutils/inetutils-${version}.tar.gz"
        "https://ftp.gnu.org/gnu/inetutils/inetutils-${version}.tar.gz"
      ];
      hash = "sha256-V7PPT3dVWZKIHluioJpjsFqixWNCpg7UMFtfRZODkLU=";
    };

    buildDeps = [gnumake perl];
    runtimeDeps = [ncurses libxcrypt];
    propagatedDeps = [];
    configureFlags = "--with-ncurses-include-dir=${ncurses}/include";
    # Inetutils 2.8 adds -Wno-format, which conflicts with the stdenv's
    # mandatory -Wformat-security hardening. Keep format checking enabled.
    makeFlags = "WARN_CFLAGS=-Wformat";

    postPatch = ''
      # Store paths cannot carry effective setuid permissions. A system module
      # supplies the required ping privilege at activation time.
      sed -i 's/^SUIDMODE = -o root -m 4755$/SUIDMODE = -m 0755/' ping/Makefile.in
      sed -i 's/^SUIDMODE = -o root -m 4755$/SUIDMODE = -m 0755/' src/Makefile.in

      grep -rlZ -e '^#! */usr/bin/perl' -e '^#! */usr/bin/env perl' . \
        | while IFS= read -r -d "" file; do
          sed -i "1s|^#!.*|#!${perl}/bin/perl|" "$file"
        done
      grep -rlZ -e '^#! */bin/sh' -e '^#! */bin/bash' -e '^#! */usr/bin/env' . \
        | while IFS= read -r -d "" file; do
          sed -i "1s|^#!.*|#!$CONFIG_SHELL|" "$file"
        done
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-inetutils";
        tool = self;
        command = "ping --version && traceroute --version && telnet --version && ftp --version";
      };
    };

    meta = {
      description = "GNU collection of common network programs";
      homepage = "https://www.gnu.org/software/inetutils/";
      license = "GPL-3.0-or-later";
    };
  }
