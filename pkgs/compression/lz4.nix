##! LZ4 — Extremely fast compression algorithm
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "1.10.0";
in
  mkDerivation {
    pname = "lz4";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/lz4/lz4/releases/download/v${version}/lz4-${version}.tar.gz"
      ];
      hash = "sha256-U3USkEdEs14jKRIFXM+Oxm12hjn/Or5XiNkNeS7F9Is=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    # The build machine's uname remains Linux during a cross build. Tell the
    # upstream makefiles which target naming and install-name rules to use.
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd lz4-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out -j$NIX_BUILD_CORES ${
            if stdenv.hostPlatform.isDarwin
            then "TARGET_OS=Darwin"
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out ${
            if stdenv.hostPlatform.isDarwin
            then "TARGET_OS=Darwin"
            else ""
          }
        '';
      }
    ];

    meta = {
      description = "LZ4 — extremely fast compression algorithm";
      homepage = "https://lz4.org";
      license = "BSD-2-Clause";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-lz4";
        library = self;
        libs = ["-llz4"];
        testSource = ''
          #include <lz4.h>
          #include <stdio.h>
          int main() {
            printf("lz4 version: %s\n", LZ4_versionString());
            return 0;
          }
        '';
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["liblz4.so"];
      };

      cli-roundtrip = testing.mkVMTest {
        name = "lib-lz4-cli-roundtrip";
        rootfsDeps = [self];
        testScript = ''
          echo "lz4 round-trip test data 1234567890" > /tmp/original.txt
          lz4 /tmp/original.txt /tmp/compressed.lz4
          lz4 -d /tmp/compressed.lz4 /tmp/decompressed.txt
          ORIG=$(cat /tmp/original.txt)
          RESULT=$(cat /tmp/decompressed.txt)
          if [ "$ORIG" != "$RESULT" ]; then
            echo "==> ERROR: decompressed data does not match original" >&2
            exit 1
          fi
          echo "==> lz4 CLI round-trip: PASS"
        '';
      };
    };
  }
