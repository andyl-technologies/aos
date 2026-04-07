# stdenv/toolchains/gcc4_4/perl.nix — Perl 5.10.1 (RHEL 6)
#
# Built with THIS tier's GCC 4.4.7 + glibc 2.5 from prev.
# Perl uses its own Configure script (not autoconf).
# Minimal build — just enough to run autoconf, automake, texinfo, help2man.
#
{
  prev,
  gcc,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://www.cpan.org/src/5.0/perl-5.10.1.tar.bz2";
    hash = "0wfch7jkcwmi5xmsrb7j18fn63hs7qvl958gzy6mfgxar6hj88dk";
  };
in
builtins.derivation {
  name = "perl-5.10.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} perl-5.10.1
      cd perl-5.10.1
      chmod -R u+w .

      # CC wrapper: appends NSS libs at link time (after object files)
      mkdir -p "$TMPDIR/ccwrap"
      cat > "$TMPDIR/ccwrap/gcc" << 'CCEOF'
#!/bin/sh
compile=
for arg; do case "$arg" in -c|-E|-S) compile=1 ;; esac; done
if [ -z "$compile" ]; then
  exec REAL_GCC -isystem GLIBC_INCLUDE "$@" -L GLIBC_LIB -static -Wl,--start-group -Wl,--whole-archive NSS_FILES NSS_DNS NSS_RESOLV -Wl,--no-whole-archive -lc -Wl,--end-group
fi
exec REAL_GCC -isystem GLIBC_INCLUDE "$@"
CCEOF
      ${prev.sed}/bin/sed -i \
        -e "s|REAL_GCC|${gcc}/bin/gcc|g" \
        -e "s|NSS_FILES|${prev.glibc}/lib/libnss_files.a|g" \
        -e "s|NSS_DNS|${prev.glibc}/lib/libnss_dns.a|g" \
        -e "s|NSS_RESOLV|${prev.glibc}/lib/libresolv.a|g" \
        -e "s|GLIBC_INCLUDE|${prev.glibc}/include|g" \
        -e "s|GLIBC_LIB|${prev.glibc}/lib|g" \
        "$TMPDIR/ccwrap/gcc"
      chmod +x "$TMPDIR/ccwrap/gcc"

      # Remove problematic extensions before Configure:
      # IO-Compress: pure Perl, no XS — Configure adds to static_ext, linker fails
      # Errno: needs C preprocessor to parse headers — fails in Nix sandbox
      rm -rf ext/IO-Compress ext/Errno
      ${prev.sed}/bin/sed -i -e '/^ext\/IO-Compress/d' -e '/^ext\/Errno/d' MANIFEST

      # Perl's Configure is its own beast — not autoconf-based.
      # Use -des for non-interactive, -Dcc for compiler, etc.
      ./Configure \
        -des \
        -Dprefix="$out" \
        -Dcc="$TMPDIR/ccwrap/gcc" \
        -Dar="${prev.binutils}/bin/ar" \
        -Dnm="${prev.binutils}/bin/nm" \
        -Dranlib="${prev.binutils}/bin/ranlib" \
        -Dsh="${prev.bash}/bin/bash" \
        -Dlocincpth="${prev.glibc}/include" \
        -Dloclibpth="${prev.glibc}/lib" \
        -Dglibpth="${prev.glibc}/lib" \
        -Dusrinc="${prev.glibc}/include" \
        -Dccflags="-O2 -I${prev.glibc}/include" \
        -Dcppflags="-I${prev.glibc}/include" \
        -Dldflags="-L${prev.glibc}/lib" \
        -Dlddlflags="-shared -L${prev.glibc}/lib" \
        -Dlibs="-lm -lpthread -lcrypt" \
        -Uuselargefiles \
        -Dusethreads=n \
        -Duseshrplib=n \
        -Dd_setlocale=undef \
        -Ui_db \
        -Ui_gdbm \
        -Ui_ndbm \
        -Dd_dosuid=undef \
        -Dd_suidsafe=undef \
        -Dman1dir=none \
        -Dman3dir=none

      # Pre-generate Errno.pm with standard Linux error codes
      cat > lib/Errno.pm << 'ERREOF'
package Errno;
use strict;
require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(EPERM ENOENT ESRCH EINTR EIO ENXIO E2BIG ENOEXEC EBADF
  ECHILD EAGAIN ENOMEM EACCES EFAULT ENOTBLK EBUSY EEXIST EXDEV ENODEV
  ENOTDIR EISDIR EINVAL ENFILE EMFILE ENOTTY ETXTBSY EFBIG ENOSPC ESPIPE
  EROFS EMLINK EPIPE EDOM ERANGE EDEADLK ENAMETOOLONG ENOLCK ENOSYS
  ENOTEMPTY ELOOP EWOULDBLOCK ENOMSG EIDRM EOVERFLOW EILSEQ ENOTSOCK
  EDESTADDRREQ EMSGSIZE EPROTOTYPE ENOPROTOOPT EPROTONOSUPPORT EOPNOTSUPP
  EAFNOSUPPORT EADDRINUSE EADDRNOTAVAIL ENETDOWN ENETUNREACH ECONNABORTED
  ECONNRESET ENOBUFS EISCONN ENOTCONN ETIMEDOUT ECONNREFUSED EHOSTUNREACH
  EALREADY EINPROGRESS ESTALE EDQUOT);
our %EXPORT_TAGS = (POSIX => [qw(E2BIG EACCES EADDRINUSE EADDRNOTAVAIL
  EAFNOSUPPORT EAGAIN EALREADY EBADF EBUSY ECHILD ECONNABORTED ECONNREFUSED
  ECONNRESET EDEADLK EDESTADDRREQ EDOM EDQUOT EEXIST EFAULT EFBIG
  EHOSTUNREACH EIDRM EILSEQ EINPROGRESS EINTR EINVAL EIO EISCONN EISDIR
  ELOOP EMFILE EMLINK EMSGSIZE ENAMETOOLONG ENETDOWN ENETRESET ENETUNREACH
  ENFILE ENOBUFS ENODEV ENOENT ENOEXEC ENOLCK ENOMEM ENOMSG ENOPROTOOPT
  ENOSPC ENOSYS ENOTCONN ENOTDIR ENOTEMPTY ENOTSOCK ENOTTY ENXIO
  EOPNOTSUPP EOVERFLOW EPERM EPIPE EPROTONOSUPPORT EPROTOTYPE ERANGE EROFS
  ESRCH ESTALE ETIMEDOUT ETXTBSY EWOULDBLOCK EXDEV)]);
sub EPERM () {1} sub ENOENT () {2} sub ESRCH () {3} sub EINTR () {4}
sub EIO () {5} sub ENXIO () {6} sub E2BIG () {7} sub ENOEXEC () {8}
sub EBADF () {9} sub ECHILD () {10} sub EAGAIN () {11} sub ENOMEM () {12}
sub EACCES () {13} sub EFAULT () {14} sub ENOTBLK () {15} sub EBUSY () {16}
sub EEXIST () {17} sub EXDEV () {18} sub ENODEV () {19} sub ENOTDIR () {20}
sub EISDIR () {21} sub EINVAL () {22} sub ENFILE () {23} sub EMFILE () {24}
sub ENOTTY () {25} sub ETXTBSY () {26} sub EFBIG () {27} sub ENOSPC () {28}
sub ESPIPE () {29} sub EROFS () {30} sub EMLINK () {31} sub EPIPE () {32}
sub EDOM () {33} sub ERANGE () {34} sub EDEADLK () {35}
sub ENAMETOOLONG () {36} sub ENOLCK () {37} sub ENOSYS () {38}
sub ENOTEMPTY () {39} sub ELOOP () {40} sub EWOULDBLOCK () {11}
sub ENOMSG () {42} sub EIDRM () {43} sub EOVERFLOW () {75}
sub EILSEQ () {84} sub ENOTSOCK () {88} sub EDESTADDRREQ () {89}
sub EMSGSIZE () {90} sub EPROTOTYPE () {91} sub ENOPROTOOPT () {92}
sub EPROTONOSUPPORT () {93} sub EOPNOTSUPP () {95} sub EAFNOSUPPORT () {97}
sub EADDRINUSE () {98} sub EADDRNOTAVAIL () {99} sub ENETDOWN () {100}
sub ENETUNREACH () {101} sub ENETRESET () {102} sub ECONNABORTED () {103}
sub ECONNRESET () {104} sub ENOBUFS () {105} sub EISCONN () {106}
sub ENOTCONN () {107} sub ETIMEDOUT () {110} sub ECONNREFUSED () {111}
sub EHOSTUNREACH () {113} sub EALREADY () {114} sub EINPROGRESS () {115}
sub ESTALE () {116} sub EDQUOT () {122}
sub TIEHASH { bless [] }
sub FETCH { my ($self, $errname) = @_; my $v = eval "no strict; &$errname"; defined $v && $v == $! + 0 }
sub STORE { require Carp; Carp::confess("ERRNO hash is read only!") }
sub EXISTS { my ($self, $errname) = @_; eval { no strict; &$errname }; !$@ }
tie %!, __PACKAGE__;
our $VERSION = "1.11";
1;
ERREOF

      # Patch Cwd.pm: miniperl can't load XS, so cwd() uses pure Perl fallback.
      # The fallback looks for /bin/pwd which doesn't exist in Nix sandbox,
      # falls through to _perl_getcwd -> abs_path('.') -> infinite loop.
      # Fix: inject our coreutils pwd path so _backtick_pwd is used instead.
      ${prev.sed}/bin/sed -i "s|'/bin/pwd'|'${prev.coreutils}/bin/pwd', '/bin/pwd'|" lib/Cwd.pm

      # Build with -j1 to avoid CWD race conditions in ext/ builds
      make -j1
      # installman fails loading POSIX autosplit files; skip it
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true || true
      test -f "$out/bin/perl" || { echo "FATAL: perl not installed"; exit 1; }

      echo "Perl 5.10.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    build = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
    execute = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
  };
}
