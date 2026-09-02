##! meson — Build system designed for speed
{
  mkDerivation,
  fetchurl,
  bash,
  python3,
}: let
  version = "1.10.1";
in
  mkDerivation {
    pname = "meson";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/mesonbuild/meson/releases/download/${version}/meson-${version}.tar.gz"
      ];
      hash = "sha256-xCKW8S2zFqRRW5N1pd8zDy51HM3U9ghDDUHX1iEOQxc=";
    };

    buildDeps = [python3];
    runtimeDeps = [
      bash
      python3
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd meson-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # No configure step — meson is a pure Python package
          true
        '';
      }
      {
        name = "build";
        script = ''
          # No build step — meson is installed by copying Python modules
          true
        '';
      }
      {
        name = "install";
        script = ''
                  mkdir -p $out/bin $out/lib/python3/site-packages

                  # Install the mesonbuild Python package and entry point
                  cp -r mesonbuild $out/lib/python3/site-packages/
                  cp meson.py $out/lib/python3/site-packages/

                  # Create wrapper script that invokes meson via python3
                  cat > $out/bin/meson << EOF
          #!${bash}/bin/bash
          PYTHONPATH=$out/lib/python3/site-packages exec ${python3}/bin/python3 -m mesonbuild.mesonmain "\$@"
          EOF
                  chmod +x $out/bin/meson
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "build-meson";
        tool = self;
        command = "meson --version";
        extraDeps = [pkgs.ninja];
      };

      build = testing.mkVMTest {
        name = "build-meson-build";
        rootfsDeps = [
          self
          pkgs.ninja
        ];
        testScript = ''
          mkdir -p /tmp/proj
          cat > /tmp/proj/meson.build << 'EOF'
          project('test', 'c')
          executable('test_app', 'main.c')
          EOF
          cat > /tmp/proj/main.c << 'EOF'
          #include <stdio.h>
          int main() { printf("meson works\n"); return 0; }
          EOF
          cd /tmp/proj
          meson setup build
          ninja -C build
          result=$(./build/test_app)
          test "$result" = "meson works"
          echo "==> meson-build passed"
        '';
      };
    };

    meta = {
      description = "Build system designed for speed";
      homepage = "https://mesonbuild.com/";
      license = "Apache-2.0";
    };
  }
