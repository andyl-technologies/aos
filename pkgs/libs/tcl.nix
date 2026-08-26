##! Tcl — Tool Command Language runtime and development library
{
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
  buildPackages,
  stdenv,
}: let
  version = "9.0.2";
in
  mkDerivation {
    pname = "tcl";
    inherit version;

    src = fetchurl {
      urls = [
        "https://prdownloads.sourceforge.net/tcl/tcl${version}-src.tar.gz"
      ];
      hash = "sha256-4HTGqNm6LN35FLqXtmd6VS16UqPKECkkOJoFzLJJtSA=";
    };

    buildDeps =
      [gnumake]
      ++ (
        if stdenv.isCross
        then [buildPackages.tcl]
        else []
      );
    runtimeDeps = [zlib];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd tcl${version}/unix
        '';
      }
      {
        name = "configure";
        script = ''
          ${
            if stdenv.isCross
            then ''export ac_cv_path_tclsh="${buildPackages.tcl}/bin/tclsh9.0"''
            else ""
          }
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --enable-threads \
            --enable-64bit
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
          make install-private-headers
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      cli = testing.mkToolCheck {
        pname = "tool-tclsh";
        tool = self;
        command = ''printf 'puts [info patchlevel]\n' | tclsh9.0'';
        expectedOutput = version;
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libtcl9.0.so"];
      };
    };

    meta = {
      description = "Tcl embeddable scripting language and runtime";
      homepage = "https://www.tcl-lang.org/";
      license = "TCL";
    };
  }
