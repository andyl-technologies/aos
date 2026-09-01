##! GNU bc — Arbitrary precision calculator language
{
  mkDerivation,
  fetchurl,
  gnumake,
  buildPackages,
  stdenv,
}: let
  version = "1.07.1";
in
  mkDerivation {
    pname = "bc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/bc/bc-${version}.tar.gz"
      ];
      hash = "sha256-Yq38qJsKHAFkws3KWcohDB1Ew//Eba+ZMc9JQmZMsCo=";
    };

    buildDeps =
      [gnumake]
      ++ (
        if stdenv.isCross
        then [buildPackages.bc]
        else []
      );
    runtimeDeps = [];
    propagatedDeps = [];

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
                    $configureFlags \
                    --prefix=$out \
                    --with-readline=no

                  ${
            if stdenv.isCross
            then ''
              # The libmath header rule links and executes a temporary `fbc`
              # with the target compiler.  Use the native bc compiler for the
              # generation step while retaining the complete target build.
              sed -i 's|\./fbc -c|${buildPackages.bc}/bin/bc -c|' bc/Makefile
            ''
            else ""
          }

                  # Replace fix-libmath_h: the original uses 'ed' to transform fbc
                  # output into a C char* array initializer.  Replicate with sed.
                  # Original ed commands:
                  #   1,1s/^/{"/    — prepend {" to first line
                  #   1,$s/$/",/    — append ", to all lines
                  #   2,$s/^/"/     — prepend " to lines 2+
                  #   $,$d          — delete last (empty) line
                  #   $,$s/,$/,0}/  — replace trailing , with ,0} on last line
                  cat > bc/fix-libmath_h << 'FIXSCRIPT'
          #!@CONFIG_SHELL@
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
                  sed -i "1s|@CONFIG_SHELL@|$CONFIG_SHELL|" bc/fix-libmath_h
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

    checks = {
      testing,
      self,
      pkgs,
    }: {
      calc = testing.mkVMTest {
        name = "tool-bc-calc";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          RESULT=$(echo "2+3" | bc)
          if [ "$RESULT" != "5" ]; then
            echo "FAIL: expected 5, got '$RESULT'" >&2
            exit 1
          fi

          # Test exponentiation
          RESULT2=$(echo "2^10" | bc)
          test "$RESULT2" = "1024"

          # Test scale/decimals
          RESULT3=$(echo "scale=2; 100/3" | bc)
          test "$RESULT3" = "33.33"

          echo "==> bc calc: passed"
        '';
      };
    };

    meta = {
      description = "GNU bc — arbitrary precision calculator language";
      homepage = "https://www.gnu.org/software/bc/";
      license = "GPL-3.0-or-later";
    };
  }
