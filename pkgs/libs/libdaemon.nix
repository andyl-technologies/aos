##! libdaemon — Lightweight C library for writing Unix daemons
{
  mkDerivation,
  fetchurl,
  gnumake,
  file,
}: let
  version = "0.14";
in
  mkDerivation {
    pname = "libdaemon";
    inherit version;

    src = fetchurl {
      urls = [
        "https://0pointer.de/lennart/projects/libdaemon/libdaemon-${version}.tar.gz"
      ];
      hash = "sha256-/SPrX2+Ybcx+cIMHNVujKJq+A8w4H8R6gLykpQqmuDQ=";
    };

    buildDeps = [gnumake file];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libdaemon-${version}

          sed -i 's|/usr/bin/file|${file}/bin/file|g' configure
        '';
      }
      {
        name = "configure";
        script = ''
          "$CONFIG_SHELL" ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-shared \
            --disable-static
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    meta = {
      description = "Lightweight C library for writing Unix daemons";
      homepage = "https://0pointer.de/lennart/projects/libdaemon/";
      license = "LGPL-2.1-or-later";
    };
  }
