##! dosfstools — Utilities for making and checking FAT filesystems
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "4.2";
in
  mkDerivation {
    pname = "dosfstools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/dosfstools/dosfstools/releases/download/v${version}/dosfstools-${version}.tar.gz"
      ];
      hash = "sha256-ZJJu6/kAktyiGxQlmlMBt7mOexlD6KIBx9cmCEgJtSc=";
    };

    patches =
      if stdenv.hostPlatform.isDarwin
      then [./dosfstools-patches/0001-limit-sysmacros-to-linux.patch]
      else [];

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd dosfstools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-compat-symlinks
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
      description = "Utilities for making and checking FAT filesystems";
      homepage = "https://github.com/dosfstools/dosfstools";
      license = "GPL-3.0-or-later";
    };
  }
