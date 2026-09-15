##! xxhash — Fast non-cryptographic hash library and checksum tool
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.8.3";
in
  mkDerivation {
    pname = "xxhash";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/Cyan4973/xxHash/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-quYI3+ghPf0F2QmldxjvgvMHIsOSNEWD0/OQUMfymoA=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd xxHash-${version}
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install PREFIX="$out"
          "$out/bin/xxhsum" --version 2>&1 | grep -F "${version}"
        '';
      }
    ];

    meta = {
      description = "Fast non-cryptographic hash library and checksum tool";
      homepage = "https://xxhash.com/";
      license = "BSD-2-Clause";
      mainProgram = "xxhsum";
    };
  }
