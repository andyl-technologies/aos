##! liblinear — Library for large linear classification
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2.47";
  sourceVersion = "247";
in
  mkDerivation {
    pname = "liblinear";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/cjlin1/liblinear/archive/refs/tags/v${sourceVersion}.tar.gz"
      ];
      hash = "sha256-pixG8goBpGJiYEYskFch9UcdpFUNOMO2j/rPCqZAZ7Q=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd liblinear-${sourceVersion}
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" lib train predict \
            CC="$CC" CXX="$CXX"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/include" "$out/lib"
          cp linear.h "$out/include/"
          cp liblinear.so.5 "$out/lib/"
          ln -s liblinear.so.5 "$out/lib/liblinear.so"
          cp train "$out/bin/liblinear-train"
          cp predict "$out/bin/liblinear-predict"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-liblinear";
        library = self;
        libs = ["-llinear"];
        testSource = ''
          #include <linear.h>

          int main(void) {
              return liblinear_version == 247 ? 0 : 1;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-liblinear";
        tool = self;
        command = "printf '1 1:1\n-1 1:-1\n' >/tmp/train && liblinear-train -q /tmp/train /tmp/model && test -s /tmp/model";
      };
    };

    meta = {
      description = "Library for large linear classification";
      homepage = "https://www.csie.ntu.edu.tw/~cjlin/liblinear/";
      license = "BSD-3-Clause";
    };
  }
