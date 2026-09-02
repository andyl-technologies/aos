{
  mkDerivation,
  fetchurl,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  gnumake,
  coreutils,
  sed,
  bash,
  grep,
}: let
  version = "1.13";
in
  mkDerivation {
    pname = "gzip";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/gzip/gzip-${version}.tar.xz"];
      hash = "0mx0j7765l4cyj3hyvlks2s3izdyzaqf3hknamjwc5yv6mlynm3l";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake coreutils sed];
    runtimeDeps = [bash grep];
    postInstall = ''
      for f in "$out/bin/"*; do
        [ -f "$f" ] || continue
        [ "$(head -c 2 "$f" 2>/dev/null)" = "#!" ] || continue
        sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$f"
      done
      if [ -f "$out/bin/zgrep" ]; then
        sed -i \
          "s|/nix/store/[a-z0-9]\\{32\\}-grep-[^/]*/bin/grep|${grep}/bin/grep|g" \
          "$out/bin/zgrep"
      fi
    '';

    meta = {
      description = "GNU gzip compression utility";
      homepage = "https://www.gnu.org/software/gzip/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
