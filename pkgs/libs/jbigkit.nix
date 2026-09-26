##! JBIG-KIT — bi-level image compression and PBM conversion tools.
{
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
