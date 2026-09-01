##! npth — New GNU Portable Threads library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.8";
in
  mkDerivation {
    pname = "npth";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnupg.org/ftp/gcrypt/npth/npth-${version}.tar.bz2"
        "https://mirrors.dotsrc.org/gcrypt/npth/npth-${version}.tar.bz2"
      ];
      hash = "sha256-i9JLTyOjBl1uWybpirqc54PqT9eBBpwbNdFJaU6Qyj4=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd npth-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static
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
      description = "New GNU Portable Threads library used by the GnuPG stack";
      homepage = "https://gnupg.org/software/npth/";
      license = "LGPL-2.1-or-later";
    };
  }
