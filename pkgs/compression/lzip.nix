##! lzip — Lossless LZMA-based data compressor
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "1.26";
in
  mkDerivation {
    pname = "lzip";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.savannah.gnu.org/releases/lzip/lzip-${version}.tar.gz"
      ];
      hash = "sha256-ZBzzCWFSXL47NAzIg0NsiFTp9QMvRZ9ETeR4K2IeZXI=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd lzip-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix="$out" CPPFLAGS=-DNDEBUG CXXFLAGS=-O3
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        # Cross-target test programs run during target qualification.
        script =
          if stdenv.isCross
          then ":"
          else ''make check'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-lzip";
        tool = self;
        command = ''printf "lzip round trip\n" | lzip -c | lzip -dc | grep -q "lzip round trip"'';
      };
    };

    meta = {
      description = "Lossless data compressor based on the LZMA algorithm";
      homepage = "https://www.nongnu.org/lzip/lzip.html";
      license = "GPL-2.0-or-later";
      mainProgram = "lzip";
    };
  }
