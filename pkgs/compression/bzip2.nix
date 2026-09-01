##! bzip2 — Block-sorting file compressor
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
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

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    # The CLI build already passes -no-pie; make the policy explicit.
    hardeningDisable =
      if stdenv.hostPlatform.isDarwin
      then []
      else ["pie"];

    # Upstream's shared-library makefile hardcodes ELF sonames and names. The
    # Darwin branch reuses the same PIC objects but links the Mach-O dylib
    # explicitly. It also selects build targets instead of `all`, whose test
    # target would try to execute the freshly cross-compiled bzip2 binary.
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
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              make -j$NIX_BUILD_CORES \
                CC="$CC" \
                AR="$AR" \
                RANLIB="$RANLIB" \
                CFLAGS="$CFLAGS -fPIC -O2 -D_FILE_OFFSET_BITS=64" \
                LDFLAGS="$LDFLAGS" \
                libbz2.a bzip2 bzip2recover

              "$CC" $CFLAGS -fPIC -O2 -D_FILE_OFFSET_BITS=64 \
                -dynamiclib \
                -Wl,-install_name,$out/lib/libbz2.1.dylib \
                -Wl,-compatibility_version,1 \
                -Wl,-current_version,${version} \
                -o libbz2.${version}.dylib \
                blocksort.o huffman.o crctable.o randtable.o \
                compress.o decompress.o bzlib.o
            ''
            else ''
              make -j$NIX_BUILD_CORES \
                CC=$CC \
                CFLAGS="$CFLAGS -fPIC -O2 -D_FILE_OFFSET_BITS=64" \
                LDFLAGS="$LDFLAGS -no-pie"
              make -f Makefile-libbz2_so \
                CC=$CC \
                CFLAGS="$CFLAGS -fPIC -O2 -D_FILE_OFFSET_BITS=64" \
                LDFLAGS="$LDFLAGS"
            ''
          }
        '';
      }
      {
        name = "install";
        script = ''
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              make install \
                PREFIX=$out \
                CC="$CC" \
                AR="$AR" \
                RANLIB="$RANLIB" \
                CFLAGS="$CFLAGS -fPIC -O2 -D_FILE_OFFSET_BITS=64" \
                LDFLAGS="$LDFLAGS"

              cp libbz2.${version}.dylib $out/lib/
              ln -sf libbz2.${version}.dylib $out/lib/libbz2.dylib
              ln -sf libbz2.${version}.dylib $out/lib/libbz2.1.dylib
              ln -sf libbz2.${version}.dylib $out/lib/libbz2.1.0.dylib
            ''
            else ''
              make install PREFIX=$out

              # Install shared library
              cp -a libbz2.so* $out/lib/
              ln -sf libbz2.so.${version} $out/lib/libbz2.so
              ln -sf libbz2.so.${version} $out/lib/libbz2.so.1
              ln -sf libbz2.so.${version} $out/lib/libbz2.so.1.0
            ''
          }
        '';
      }
    ];

    meta = {
      description = "bzip2 — block-sorting file compressor";
      homepage = "https://sourceware.org/bzip2/";
      license = "bzip2-1.0.6";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-bzip2";
        library = self;
        libs = ["-lbz2"];
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
        rootfsDeps = [self];
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
