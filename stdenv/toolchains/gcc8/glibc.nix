# stdenv/toolchains/gcc8/glibc.nix - glibc 2.28 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + linux-headers 4.18.
{
  prev,
  gcc,
  binutils,
  linuxHeaders,
  buildPlatform,
  hostPlatform,
}:
import ../lib/mk-glibc.nix {
  inherit
    prev
    gcc
    binutils
    linuxHeaders
    buildPlatform
    hostPlatform
    ;
} {
  version = "2.28";
  url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.28.tar.xz";
  sha256 = "0lyg4znbrzixpbcwp4jkv7kv41dlk597xdizclgkc4fllz2gshzx";
  configureBuild = hostPlatform.config;
  cflags = "-O2 -Wno-error=maybe-uninitialized";
  extraPathDeps = [
    prev.bison
    prev.m4
    prev.flex
    prev.autoconf
    prev.automake
    prev.texinfo
    prev.help2man
  ];
  configureFlags = [
    "--disable-profile"
    "--disable-nscd"
    "--disable-timezone-tools"
    "--enable-static-nss"
    "--disable-multi-arch"
    "--without-gd"
    "--without-selinux"
  ];
  configureCacheVars = [
    "libc_cv_forced_unwind=yes"
    "libc_cv_c_cleanup=yes"
  ];
  copyLinuxHeadersNoPreserve = true;
  postUnpack = ''
    # Patch plural.y: replace bison 2.7+ directive with 2.4 equivalent.
    ${prev.sed}/bin/sed -i 's/%define api.pure full/%pure-parser/' intl/plural.y

    # Touch gperf inputs first, then outputs, so make doesn't regenerate them.
    find . -type f -name '*.gperf' -exec touch {} + 2>/dev/null || true
    sleep 1
    find . -type f -name '*-kw.h' -exec touch {} + 2>/dev/null || true
  '';
  finalMessage = "glibc 2.28 installed to $out";
  meta = {
    description = "GNU C Library, version 2.28";
    homepage = "https://www.gnu.org/software/libc/";
    license = "LGPL-2.1-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
