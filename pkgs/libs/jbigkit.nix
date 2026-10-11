##! JBIG-KIT — bi-level image compression and PBM conversion tools.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "2.1";
  libraryExtension =
    if stdenv.hostPlatform.isDarwin
    then "dylib"
    else "so";
  sharedFlags =
    if stdenv.hostPlatform.isDarwin
    then "-dynamiclib"
    else "-shared";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "jbigkit";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A two-row, eight-pixel monochrome PBM image.";
        operation = "Compress the bitmap to JBIG and decode it back to PBM.";
        expected = "The decoded bitmap preserves both pixel rows.";
        files."probe.pbm" = "P1\n8 2\n0 0 1 1 1 1 0 0\n0 1 0 0 0 0 1 0\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/pbmtojbg" "probe.pbm" "probe.jbg"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/jbgtopbm" "probe.jbg" "roundtrip.pbm"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                from pathlib import Path

                bitmap = Path("roundtrip.pbm").read_bytes()
                assert bitmap.startswith(b"P4\n")
                assert bitmap.splitlines()[1:3] == [b"         8", b"         2"]
                assert bitmap.endswith(bytes((0x3c, 0x42)))
                print("jbigkit bitmap round trip passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "jbigkit bitmap round trip passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A truncated JBIG stream.";
        operation = "Attempt to decode it as a bitmap.";
        expected = "The decoder rejects it with status 1.";
        files."broken.jbg" = "not a JBIG stream\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/jbgtopbm" "broken.jbg" "broken.pbm"];
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://www.cl.cam.ac.uk/~mgk25/jbigkit/download/jbigkit-${version}.tar.gz"];
      hash = "0cnrcdr1dwp7h7m0a56qw09bv08krb37mpf7cml5sjdgpyv0cwfy";
    };

    buildDeps = [buildPackages.gnumake buildPackages.mandoc];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
              tar xf "$src"
              cd jbigkit-${version}
              # Upstream hardcodes archive tools; cross builds need target tools.
              sed -i -e 's/\tar rc /\t$(AR) rc /' \
                -e 's/\t-ranlib /\t-$(RANLIB) /' libjbig/Makefile
            sed -i 's/groff -man -Tascii -P -c -P -b -P -u/mandoc -Tascii/' pbmtools/Makefile
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL" \
              CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-O2 -fPIC"

            # Upstream builds static archives only. Reuse the PIC objects for the
            # same public APIs in shared libraries, without changing the codecs.
            $CC ${sharedFlags} libjbig/jbig.o libjbig/jbig_ar.o \
              -o libjbig/libjbig.${libraryExtension}
            $CC ${sharedFlags} libjbig/jbig85.o libjbig/jbig_ar.o \
              -o libjbig/libjbig85.${libraryExtension}
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              make test SHELL="$CONFIG_SHELL" CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-O2 -fPIC"
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin" "$out/lib" "$out/include" \
              "$out/share/man/man1" "$out/share/man/man5" \
              "$out/share/doc/jbigkit" "$out/share/licenses/jbigkit"
            cp libjbig/*.a libjbig/*.${libraryExtension} "$out/lib/"
            cp libjbig/jbig.h libjbig/jbig85.h libjbig/jbig_ar.h "$out/include/"
            cp pbmtools/pbmtojbg pbmtools/jbgtopbm \
              pbmtools/pbmtojbg85 pbmtools/jbgtopbm85 "$out/bin/"
            cp pbmtools/*.1 "$out/share/man/man1/"
            cp pbmtools/*.5 "$out/share/man/man5/"
            cp libjbig/*.txt pbmtools/*.txt "$out/share/doc/jbigkit/"
            cp COPYING "$out/share/licenses/jbigkit/"
          '';
        }
      ];

    meta = {
      description = "JBIG1 and T.85 image compression libraries and conversion tools";
      homepage = "https://www.cl.cam.ac.uk/~mgk25/jbigkit/";
      license = "GPL-2.0-or-later";
    };
  }
