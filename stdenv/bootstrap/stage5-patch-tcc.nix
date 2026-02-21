# stdenv/bootstrap/stage5-patch.nix — GNU patch 2.5.9 from TCC (Mes libc)
#
# Built with TCC via configure+make. sed and grep are available at this
# stage, so configure can run normally.
#
# Builder: bash 2.05b (TCC-compiled, stage 4)
#
{
  tinycc, # Output of stage3 (TCC 0.9.27 with Mes libc)
  posix-tools, # Output of stage1-posix-tools.nix
  bash, # Output of stage4-bash.nix
  gnumake, # GNU Make 3.79.1 from TCC
  sed, # GNU sed 3.02 from TCC
  grep, # GNU grep 2.4 from TCC
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;

  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.5.9.tar.gz";
    sha256 = "sha256-LiyweTmLg8H9PeHjwfJAPO34y//rF+mD+7IdsozDzLM=";
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
  name = "patch-2.5.9";
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
            grep
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
      echo "==> Configuring GNU patch 2.5.9"
      $CONFIG_SHELL ./configure \
        CC=tcc \
        AR="tcc -ar" \
        RANLIB=true \
        LDFLAGS="-static" \
        --build=i686-unknown-linux-gnu \
        --host=i686-unknown-linux-gnu \
        --prefix=$out

      # ── Build ────────────────────────────────────────────────────────────
      echo "==> Building GNU patch 2.5.9"
      make

      # ── Install ──────────────────────────────────────────────────────────
      echo "==> Installing GNU patch 2.5.9"
      make install

      echo "patch 2.5.9 built successfully"
    ''
  ];
}
// {
  meta = {
    description = "GNU patch 2.5.9 — built from TCC for bootstrap";
    license = "GPL-3.0-or-later";
    platforms = [ "i686-linux" ];
  };
}
