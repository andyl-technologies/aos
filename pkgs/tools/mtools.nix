##! mtools — utilities for accessing MS-DOS disks
{
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
  stdenv,
}: let
  version = "4.0.44";
in
  mkDerivation {
    pname = "mtools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/mtools/mtools-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/mtools/mtools-${version}.tar.gz"
      ];
      hash = "sha256-EL52FIhw+YT6RN8pdHOk5FGERyzbGaTQXvF/21m11aQ=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [bash]
      else [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd mtools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --without-x
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
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            for script in amuFormat.sh mcheck mcomp mxtar tgz uz; do
              [ -f "$out/bin/$script" ] || continue
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/$script"
            done
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "mtools — utilities for accessing MS-DOS disks";
      homepage = "https://www.gnu.org/software/mtools/";
      license = "GPL-3.0-or-later";
    };
  }
