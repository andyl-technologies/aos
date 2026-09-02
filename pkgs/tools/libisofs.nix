##! libisofs — ISO9660 filesystem reader/writer
##!
##! Companion to libburn; together with libisoburn provides the xorriso
##! CLI. AOS uses xorriso to produce the `aos-metadata` ISO consumed
##! by the VM test harness and bare-metal operators via IPMI virtual
##! media.
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  acl,
  attr,
  stdenv,
}: let
  version = "1.5.6";
in
  mkDerivation {
    pname = "libisofs";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.libburnia-project.org/releases/libisofs-${version}.tar.gz"
      ];
      hash = "sha256-AVLWap00C2Wf6ciA65GQ81cPtHesB89S6LzRNKHTDXA=";
    };

    buildDeps = [gnumake pkg-config];
    # GNU attr and libacl implement Linux syscall/ELF compatibility layers.
    # Upstream libisofs selects no ACL/xattr backend on Darwin, so do not pull
    # those explicitly Linux-only packages into an otherwise portable build.
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [zlib]
      else [zlib acl attr];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            tar xf $src
            cd libisofs-${version}

            # rockridge.h exposes ssize_t directly. Linux happens to acquire
            # it through transitive includes, while Darwin correctly requires
            # the defining POSIX header.
            sed -i '42i#include <sys/types.h>' libisofs/rockridge.h
          ''
          else ''
            tar xf $src
            cd libisofs-${version}
          '';
      }
      {
        name = "configure";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            # Darwin provides iconv in libSystem, but the Autoconf probe cannot
            # execute its test binary while cross-compiling.
            # Upstream defaults to a debug build and records the ephemeral
            # source tree in every Mach-O dylib. Select its release mode and
            # seed CFLAGS so configure does not add debug information.
            CFLAGS="-O2" LIBISOFS_ASSUME_ICONV=yes \
              ./configure $configureFlags --disable-debug --prefix=$out
          ''
          else ''
            ./configure $configureFlags --prefix=$out
          '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "libisofs — ISO9660 filesystem reader/writer";
      homepage = "https://dev.lovelyhq.com/libburnia/";
      license = "GPL-2.0-or-later";
    };
  }
