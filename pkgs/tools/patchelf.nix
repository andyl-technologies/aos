##! patchelf — Utility for modifying ELF executables
{
  mkDerivation,
  fetchurl,
  stdenv,
  gnumake,
}: let
  version = "0.18.0";
in
  mkDerivation {
    pname = "patchelf";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/NixOS/patchelf/releases/download/${version}/patchelf-${version}.tar.bz2"
      ];
      hash = "sha256-GVKyp4K6V2J5whHulC40F0j9tEmX9wTdU970bNBVRws=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd patchelf-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ${
            if stdenv.isCross
            then "$CONFIG_SHELL ./configure $configureFlags"
            else "./configure"
          } --prefix=$out
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
      description = "Utility for modifying ELF executables and libraries";
      homepage = "https://github.com/NixOS/patchelf";
      license = "GPL-3.0-or-later";
    };
  }
