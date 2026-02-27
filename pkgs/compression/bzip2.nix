##! bzip2 — Block-sorting file compressor
{
  mkDerivation,
  fetchurl,
  gnumake,
}:
let
  version = "1.0.8";
in
mkDerivation {
  pname = "bzip2";
  inherit version;

  src = fetchurl {
    urls = [
      "https://sourceware.org/pub/bzip2/bzip2-${version}.tar.gz"
    ];
    hash = "sha256-q1oDF27hBtPw+pDjgdpHjdrkBZGBU8yiSOaCzQxKImk=";
  };

  buildDeps = [ gnumake ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd bzip2-${version}
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES \
          CC=$CC \
          CFLAGS="$CFLAGS -fPIC -O2 -D_FILE_OFFSET_BITS=64" \
          LDFLAGS="$LDFLAGS"
        make -f Makefile-libbz2_so \
          CC=$CC \
          CFLAGS="$CFLAGS -fPIC -O2 -D_FILE_OFFSET_BITS=64" \
          LDFLAGS="$LDFLAGS"
      '';
    }
    {
      name = "install";
      script = ''
        make install PREFIX=$out
        # Install shared library
        cp -a libbz2.so* $out/lib/
        ln -sf libbz2.so.${version} $out/lib/libbz2.so
        ln -sf libbz2.so.${version} $out/lib/libbz2.so.1
        ln -sf libbz2.so.${version} $out/lib/libbz2.so.1.0
      '';
    }
  ];

  meta = {
    description = "bzip2 — block-sorting file compressor";
    homepage = "https://sourceware.org/bzip2/";
    license = "bzip2-1.0.6";
  };

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      link = testing.mkLinkCheck {
        pname = "lib-bzip2";
        library = self;
        libs = [ "-lbz2" ];
        testSource = ''
          #include <bzlib.h>
          #include <stdio.h>
          int main() {
            printf("bzip2 version: %s\n", BZ2_bzlibVersion());
            return 0;
          }
        '';
      };

      cli-roundtrip = testing.mkVMTest {
        name = "lib-bzip2-cli-roundtrip";
        rootfsDeps = [ self ];
        testScript = ''
          echo "bzip2 round-trip test data 1234567890" > /tmp/original.txt
          cp /tmp/original.txt /tmp/tocompress.txt
          bzip2 /tmp/tocompress.txt
          bunzip2 /tmp/tocompress.txt.bz2
          ORIG=$(cat /tmp/original.txt)
          RESULT=$(cat /tmp/tocompress.txt)
          if [ "$ORIG" != "$RESULT" ]; then
            echo "==> ERROR: decompressed data does not match original" >&2
            exit 1
          fi
          echo "==> bzip2 CLI round-trip: PASS"
        '';
      };
    };
}
