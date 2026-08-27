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
}: let
  version = "4.4";
in
  mkDerivation (
    {
      pname = "gnumake";
      inherit version;

      src = fetchurl {
        urls = ["https://mirrors.kernel.org/gnu/make/make-${version}.tar.gz"];
        hash = "062x21wpjjhxxv6bscipy015ilx7k1c22x6884wlp9rdhx74s7sq";
      };

      # The cross stdenv already supplies the native make used for this bootstrap.
      buildDeps = [m4 flex bison autoconf automake texinfo];
      runtimeDeps = [];
      configureFlags = "--disable-nls";

      meta = {
        description = "GNU Make build automation tool";
        homepage = "https://www.gnu.org/software/make/";
        license = "GPL-3.0-or-later";
        platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
      };
    }
    // (
      if stdenv.isCross && stdenv.hostPlatform.isDarwin
      then {
        postPatch = ''
          # Make 4.4's bundled glob predates modern C prototypes and wraps
          # realloc with a char-pointer-only K&R interface. Darwin's Clang 22
          # correctly rejects its char ** call sites; use the standard
          # pointer-generic signature adopted by the subsequent upstream code.
          sed -i '/^my_realloc (p, n)$/,/^     unsigned int n;$/ {
            s/^     char \*p;$/     void *p;/
          }' lib/glob.c
        '';
      }
      else {}
    )
  )
