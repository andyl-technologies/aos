##! GNU bc — Arbitrary precision calculator language
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.07.1";
in
mkDerivation {
  pname = "bc";
  inherit version;

  src = fetchurl {
    urls = [
      "https://ftp.gnu.org/gnu/bc/bc-${version}.tar.gz"
    ];
    hash = "sha256-Yq38qJsKHAFkws3KWcohDB1Ew//Eba+ZMc9JQmZMsCo=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd bc-${version}
      '';
    }
    {
      name = "configure";
      script = ''
                ./configure \
                  --prefix=$out \
                  --with-readline=no

                # Replace fix-libmath_h: the original uses 'ed' to transform fbc
                # output into a C char* array initializer.  Replicate with sed.
                # Original ed commands:
                #   1,1s/^/{"/    — prepend {" to first line
                #   1,$s/$/",/    — append ", to all lines
                #   2,$s/^/"/     — prepend " to lines 2+
                #   $,$d          — delete last (empty) line
                #   $,$s/,$/,0}/  — replace trailing , with ,0} on last line
                cat > bc/fix-libmath_h << 'FIXSCRIPT'
        #!/bin/sh
        # Remove trailing empty lines
        sed -i -e :a -e '/^[[:space:]]*$/{ $d; N; ba; }' libmath.h
        # Transform into C char* array initializer: {"line1","line2",...,0}
        sed -i \
          -e '1s/^/{"/' \
          -e 's/$/",/' \
          -e '2,$s/^/"/' \
          -e '$s/,$/,0}/' \
          libmath.h
        FIXSCRIPT
                chmod +x bc/fix-libmath_h
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES MAKEINFO=true
      '';
    }
    {
      name = "install";
      script = ''
        make install MAKEINFO=true
      '';
    }
  ];

  meta = {
    description = "GNU bc — arbitrary precision calculator language";
    homepage = "https://www.gnu.org/software/bc/";
    license = "GPL-3.0-or-later";
  };
}
