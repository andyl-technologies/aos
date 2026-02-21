# stdenv/bootstrap/stage5-grep.nix — GNU grep 2.4 from TCC (Mes libc)
#
# Built with TCC via configure+make. sed is available at this stage,
# so configure can run normally.
#
# Builder: bash 2.05b (TCC-compiled, stage 4)
#
{
  tinycc, # Output of stage3 (TCC 0.9.27 with Mes libc)
  posix-tools, # Output of stage1-posix-tools.nix
  bash, # bash 2.05b from TCC (stage 4)
  gnumake, # GNU Make 3.79.1 from TCC
  sed, # GNU sed 3.02 from TCC
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;

  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/grep/grep-2.4.tar.gz";
    sha256 = "sha256-v9xxK5dLi3FxvpCbRjPorpK+bPNcAXwj/jgX4eslWxI=";
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
  name = "grep-2.4";
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
            bash
            tinycc
            gnumake
            sed
            posix-tools
          ]
        )
      }"
      export CONFIG_SHELL="${bash}/bin/bash"
      export SHELL="${bash}/bin/bash"

      # Copy source to writable directory
      mkdir $TMPDIR/src
      cpdir ${src} $TMPDIR/src
      cd $TMPDIR/src

      # ── Configure ────────────────────────────────────────────────────────
      echo "==> Configuring GNU grep 2.4"
      $CONFIG_SHELL ./configure \
        CC=tcc \
        CFLAGS="-DHAVE_UNISTD_H -DHAVE_STRERROR" \
        AR="tcc -ar" \
        RANLIB=true \
        LDFLAGS="-static" \
        --build=i686-unknown-linux-gnu \
        --host=i686-unknown-linux-gnu \
        --disable-nls \
        --prefix=$out

      # ── Build ────────────────────────────────────────────────────────────
      echo "==> Building GNU grep 2.4"
      make

      # ── Install ──────────────────────────────────────────────────────────
      echo "==> Installing GNU grep 2.4"
      make install

      echo "grep 2.4 built successfully"
    ''
  ];
}
// {
  meta = {
    description = "GNU grep 2.4 — built from TCC for bootstrap";
    license = "GPL-2.0-or-later";
    platforms = [ "i686-linux" ];
  };
}
