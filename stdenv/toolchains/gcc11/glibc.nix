# stdenv/toolchains/gcc11/glibc.nix - glibc 2.34 (RHEL 9)
#
# Built with THIS tier's GCC 11.5.0 + binutils 2.35 + linux-headers 5.14.
# glibc 2.34+ needs shared-library generation because required generated
# headers are only produced on the shared build path.
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
  version = "2.34";
  url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.34.tar.xz";
  sha256 = "1vx5ny3fg9l3mx14pdk2wccy2h11axy4lgm9wmjp2izfcid5iz1l";
  useCxx = true;
  extraPathDeps = [
    prev.bison
    prev.m4
    prev.python3
  ];
  configureFlags = [
    "--disable-profile"
    "--disable-nscd"
    "--disable-timezone-tools"
    "--disable-werror"
    "--enable-static-nss"
    "--without-gd"
    "--without-selinux"
  ];
  configureCacheVars = [
    "libc_cv_forced_unwind=yes"
    "libc_cv_c_cleanup=yes"
  ];
  makeFlags = ["build-programs=no"];
  installFlags = ["build-programs=no"];
  finalMessage = "glibc 2.34 installed to $out";
  meta = {
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
