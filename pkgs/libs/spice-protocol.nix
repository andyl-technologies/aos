##! spice-protocol — SPICE display and device protocol headers
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  python3,
  stdenv,
  buildPackages,
}: let
  version = "0.14.5";
  buildMeson =
    if stdenv.isCross
    then buildPackages.meson
    else meson;
in
  mkDerivation {
    pname = "spice-protocol";
    inherit version;

    src = fetchurl {
      urls = ["https://www.spice-space.org/download/releases/spice-protocol-${version}.tar.xz"];
      hash = "sha256-uvWESfbonRn0dYma1fuRlv3EbAPMUyM/TjnPKXj5z/c=";
    };

    buildDeps =
      if stdenv.isCross
      then [buildMeson buildPackages.ninja buildPackages.python3]
      else [buildMeson ninja python3];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd spice-protocol-${version}
          # Preserve wire prefixes while allowing real variable-length tails
          # under strict flexible-array bounds checking. Empty records and
          # nested variable-length display records retain their special layout.
          patch --batch -p1 < ${./spice-protocol-flexible-arrays.patch}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build \
            $mesonFlags \
            --prefix="$out" \
            --libdir=lib \
            --buildtype=release
        '';
      }
      {
        name = "check";
        script = ''
          gcc -std=c11 -O2 -Wall -Wextra -Werror -fstrict-flex-arrays=3 \
            -I. ${./tests/spice-protocol-layout.c} \
            -o spice-protocol-layout
          ${
            if stdenv.isCross
            then ""
            else "./spice-protocol-layout"
          }
        '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH=${buildMeson}/lib/python3/site-packages \
            ninja -C build install

          # These public headers are the complete upstream package. Keep the
          # protocol license with them for corresponding-source consumers.
          mkdir -p "$out/share/licenses/spice-protocol"
          cp COPYING "$out/share/licenses/spice-protocol/COPYING"
          test -s "$out/include/spice-1/spice/qxl_dev.h"
          test -s "$out/share/pkgconfig/spice-protocol.pc"
        '';
      }
    ];

    meta = {
      description = "SPICE display, QXL and guest device protocol headers";
      homepage = "https://www.spice-space.org/";
      license = "BSD-3-Clause";
    };
  }
