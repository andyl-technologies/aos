{
  mkDerivation,
  fetchurl,
  stdenv,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  gnumake,
  coreutils,
}: let
  version = "3.10";
in
  mkDerivation (
    {
      pname = "diffutils";
      inherit version;

      src = fetchurl {
        urls = ["https://mirrors.kernel.org/gnu/diffutils/diffutils-${version}.tar.xz"];
        hash = "17nhkdn5a2z6pwcmjs4jas2plg066hbdz06y5vhypr14qwyfkrch";
      };

      buildDeps = [m4 flex bison autoconf automake texinfo gnumake];
      runtimeDeps = [coreutils];
      configureFlags = "--disable-nls PR_PROGRAM=${coreutils}/bin/pr";

      meta = {
        description = "GNU file comparison utilities";
        homepage = "https://www.gnu.org/software/diffutils/";
        license = "GPL-3.0-or-later";
        platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
      };
    }
    // (
      if stdenv.isCross && stdenv.hostPlatform.isDarwin
      then {
        postPatch = ''
          # This old gnulib snapshot includes Apple's legacy libc.h and
          # nlist.h headers in its Mach VM implementation, but uses no
          # declarations from either. Modern Darwin SDKs expose the required
          # API through mach/mach.h directly.
          sed -i -e '/^#include <libc\.h>$/d' -e '/^#include <nlist\.h>$/d' \
            lib/stackvma.c
        '';
      }
      else {}
    )
  )
