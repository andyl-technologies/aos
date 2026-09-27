##! inetutils — GNU network utility suite
{
  mkDerivation,
  fetchurl,
  lib,
  gnumake,
  buildPackages,
  ncurses,
  libxcrypt,
  perl,
  stdenv,
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
    patches =
      [./inetutils-format-security.patch]
      ++ lib.optional stdenv.hostPlatform.isDarwin ./inetutils-darwin-ipv4-options.patch;

    buildDeps = [gnumake perl] ++ lib.optional stdenv.hostPlatform.isDarwin buildPackages.glibc.dev;
    runtimeDeps = [ncurses libxcrypt];
    propagatedDeps = [];
    configureFlags =
      "--with-ncurses-include-dir=${ncurses}/include"
      + (
        if stdenv.isCross && stdenv.hostPlatform.isLinux
        then
          # Cross configure cannot inspect the target procfs. Linux ifconfig
          # requires this kernel interface even when the build sandbox lacks it.
          " inetutils_cv_path_procnet_dev=/proc/net/dev"
        else ""
      );
    # Inetutils 2.8 adds -Wno-format, which conflicts with the stdenv's
    # mandatory -Wformat-security hardening. Keep format checking enabled.
    makeFlags = "WARN_CFLAGS=-Wformat";

    preConfigure = lib.optionalString stdenv.hostPlatform.isDarwin ''
      # The Darwin SDK omits these portable protocol headers. Use the
      # source-built AOS glibc copies to retain their network utilities.
      mkdir -p .aos-compat/arpa .aos-compat/netinet .aos-compat/protocols \
        .aos-compat/bits/types
      cp ${buildPackages.glibc.dev}/include/arpa/tftp.h .aos-compat/arpa/tftp.h
      cp ${buildPackages.glibc.dev}/include/arpa/telnet.h .aos-compat/arpa/telnet.h
      cp ${buildPackages.glibc.dev}/include/arpa/ftp.h .aos-compat/arpa/ftp.h
      cp ${buildPackages.glibc.dev}/include/protocols/*.h .aos-compat/protocols/
      cp ${buildPackages.glibc.dev}/include/bits/types/struct_osockaddr.h \
        .aos-compat/bits/types/
      cp ${./inetutils-ip6.h} .aos-compat/netinet/ip6.h
      export CPPFLAGS="-I$PWD/.aos-compat ''${CPPFLAGS:-}"
    '';

    preBuild = lib.optionalString stdenv.hostPlatform.isDarwin ''
      # Cross builds cannot run target utilities through help2man. The
      # release tarball already contains pages for the unchanged CLI.
      for page in man/*.[18]; do
        touch "$page"
      done
    '';

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
