##! strace — System call tracer for Linux
{
  mkDerivation,
  fetchurl,
  gnumake,
  linux-headers,
}: let
  version = "7.2";
in
  mkDerivation {
    pname = "strace";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/strace/strace/releases/download/v${version}/strace-${version}.tar.xz"
      ];
      hash = "sha256-S95iRpJokNzugk9uasQqBnUvR9d+UJfYbjwNbUtwn+U=";
    };

    buildDeps = [gnumake linux-headers];
    runtimeDeps = [];
    propagatedDeps = [];

    # strace builds with -Werror and uses trailing zero-length arrays as
    # flexible members; -fstrict-flex-arrays=3 then trips -Werror=array-bounds
    # (e.g. mmsghdr.c). Step down to level 1 (still hardened, but [0]/[1]
    # trailing arrays stay flexible). Same idiom as elfutils.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd strace-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-mpers \
            --enable-static=no
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "System call tracer for Linux";
      homepage = "https://strace.io/";
      license = "LGPL-2.1-or-later";
    };
  }
