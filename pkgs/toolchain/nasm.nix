##! nasm — Netwide Assembler (x86/x86-64)
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2.16.03";
in
  mkDerivation {
    pname = "nasm";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.nasm.us/pub/nasm/releasebuilds/${version}/nasm-${version}.tar.xz"
      ];
      hash = "sha256-FBKhx2C70F2wJrbA0WV6/9ZjHNCmPN229zzG1KphYUg=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd nasm-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES nasm ndisasm
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
      description = "nasm — Netwide Assembler for x86/x86-64";
      homepage = "https://www.nasm.us/";
      license = "BSD-2-Clause";
    };
  }
