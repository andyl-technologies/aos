# stdenv/bootstrap/stage8-gnumake.nix — GNU Make 3.79.1 from GCC 2.95.3 (glibc)
#
# Compiled with self-hosted GCC 2.95.3 linked against glibc 2.2.5.
# Uses configure/make (via stage4 TCC-compiled make) instead of manual
# compilation.
#
# GNU Make 3.79.1 is chosen for maximal compatibility with GCC 2.95.3 era.
#
# Builder: bash 2.05b.
#
{
  gcc, # Output of stage7-gcc.nix (self-hosted GCC 2.95.3)
  glibc, # Output of stage7-glibc.nix
  linuxHeaders, # Output of stage5-linux-headers.nix
  posix-tools, # Output of stage1-posix-tools.nix
  bash, # Output of stage4-bash.nix or stage4-bash
  gnumake, # gnumake-tcc from stage 5
  sed, # sed-tcc from stage 5 (needed by configure)
  grep, # grep-tcc from stage 5 (needed by configure)
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;

  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/make/make-3.79.1.tar.gz";
    sha256 = "sha256-0ATEyqEsirZxYPdk1ifsRqXp1KUWPLrtGgAmw/QYgYI=";
  };

  # Recursive copy helper for bootstrap (posix-tools cp handles single files)
  cpdir = ''
    cpdir() {
      for item in "$1"/*; do
        [ -e "$item" ] || continue
        base="''${item##*/}"
        if [ -d "$item" ]; then
          [ -d "$2/$base" ] || mkdir "$2/$base"
          cpdir "$item" "$2/$base"
        else
          cp "$item" "$2/$base"
        fi
      done
    }
  '';

in
builtins.derivation {
  name = "make-3.79.1";
  inherit system;
  builder = "${bash}/bin/bash";
  args = [
    "-c"
    ''
      ${cpdir}
      set -eu

      export PATH="${
        builtins.concatStringsSep ":" (
          builtins.map (p: "${p}/bin") [
            gcc
            gnumake
            sed
            grep
            posix-tools
            bash
          ]
        )
      }"

      # Copy source to writable directory
      mkdir $TMPDIR/src
      cpdir ${src} $TMPDIR/src
      cd $TMPDIR/src

      CC="${gcc}/bin/gcc" \
      CFLAGS="-I${glibc}/include -I${linuxHeaders}/include" \
      LDFLAGS="-static -L${glibc}/lib" \
      CONFIG_SHELL="${bash}/bin/bash" \
      ./configure --prefix=$out

      make
      make install

      echo "GNU Make 3.79.1 built successfully"
    ''
  ];
}
// {
  meta = {
    description = "GNU Make 3.79.1 -- built from GCC 2.95.3 with glibc for bootstrap";
    homepage = "https://www.gnu.org/software/make/";
    license = "GPL-2.0-or-later";
    platforms = [ "i686-linux" ];
  };
}
