##! inetutils — GNU network utility suite
{
  mkDerivation,
  fetchurl,
  gnumake,
  ncurses,
  libxcrypt,
  perl,
}: let
  version = "2.7";
  cve24061Part1 = fetchurl {
    urls = ["https://codeberg.org/inetutils/inetutils/commit/fd702c02497b2f398e739e3119bed0b23dd7aa7b.patch"];
    hash = "sha256-Mt+Bvtrxe8C55lf0VVvkI+e3aUv6tqj64Tm8Mwk3bYA=";
  };
  cve24061Part2 = fetchurl {
    urls = ["https://codeberg.org/inetutils/inetutils/commit/ccba9f748aa8d50a38d7748e2e60362edd6a32cc.patch"];
    hash = "sha256-nAst6VH+nSwaNn4TK8dh4zW9kt2Q2SryRqXfX/dlBO8=";
  };
  cve28372 = fetchurl {
    urls = ["https://codeberg.org/inetutils/inetutils/commit/4db2f19f4caac03c7f4da6363c140bd70df31386.patch"];
    hash = "sha256-33HZxPzNDzVQiYzieof20TuKTmnx5vQez90YbgyegPI=";
  };
  cve32746 = fetchurl {
    urls = ["https://codeberg.org/inetutils/inetutils/commit/6864598a29b652a6b69a958f5cd1318aa2b258af.patch"];
    hash = "sha256-IsngyMVDyYQuY0192xcsRID8W5dO6v5NqLz+jwtc26o=";
  };
in
  mkDerivation {
    pname = "inetutils";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftpmirror.gnu.org/gnu/inetutils/inetutils-${version}.tar.gz"
        "https://ftp.gnu.org/gnu/inetutils/inetutils-${version}.tar.gz"
      ];
      hash = "sha256-oVa+HN48XA/+/CYhgNk2mmBIQIeQeqVUxieH0vQOwIY=";
    };

    buildDeps = [gnumake perl];
    runtimeDeps = [ncurses libxcrypt];
    propagatedDeps = [];
    configureFlags = "--with-ncurses-include-dir=${ncurses}/include";

    postPatch = ''
      patch -p1 < ${cve24061Part1}
      patch -p1 < ${cve24061Part2}
      sed -n '/^diff --git a\/telnetd\/pty.c/,$p' ${cve28372} | patch -p1
      sed -n '/^diff --git a\/telnetd\/slc.c/,$p' ${cve32746} | patch -p1

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
