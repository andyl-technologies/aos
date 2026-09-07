##! lm-sensors — Hardware monitoring tools and library
{
  mkDerivation,
  fetchurl,
  gnumake,
  bison,
  flex,
  which,
  perl,
  bash,
}: let
  version = "3.6.2";
  tag = "V3-6-2";
in
  mkDerivation {
    pname = "lm-sensors";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/hramrach/lm-sensors/archive/refs/tags/${tag}.tar.gz"];
      hash = "sha256-xqBYflZXeKQNiIkZKL+JQ/J9NT84LVt0Wpl9Y1l4qPA=";
    };

    buildDeps = [gnumake bison flex which];
    runtimeDeps = [perl bash];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd lm-sensors-3-6-2
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i 's|ETCDIR "/sensors.d"|"/etc/sensors.d"|' lib/init.c
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" \
            PREFIX="$out" \
            ETCDIR="$out/etc" \
            BUILD_SHARED_LIB=1 \
            BUILD_STATIC_LIB=0
        '';
      }
      {
        name = "install";
        script = ''
          make install \
            PREFIX="$out" \
            ETCDIR="$out/etc" \
            BUILD_SHARED_LIB=1 \
            BUILD_STATIC_LIB=0

          for program in sensors-detect sensors-conf-convert; do
            if [ -f "$out/sbin/$program" ]; then
              sed -i "1s|^#!.*|#!${perl}/bin/perl|" "$out/sbin/$program"
            fi
          done
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-lm-sensors";
        library = self;
        libs = ["-lsensors"];
        testSource = ''
          #include <sensors/sensors.h>

          int main(void) {
              return sensors_init(0);
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-lm-sensors";
        tool = self;
        command = "sensors --version";
      };
    };

    meta = {
      description = "Tools and library for reading hardware sensors";
      homepage = "https://hwmon.wiki.kernel.org/lm_sensors";
      license = "LGPL-2.1-or-later AND GPL-2.0-or-later";
      mainProgram = "sensors";
    };
  }
