##! OpenPAM -- portable Pluggable Authentication Modules implementation
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  stdenv,
}: let
  version = "20250531";
in
  mkDerivation {
    pname = "openpam";
    inherit version;

    src = fetchurl {
      urls = [
        "https://downloads.sourceforge.net/project/openpam/openpam/Zingiber/openpam-${version}.tar.gz"
      ];
      hash = "sha256-wesvNpiwElgg2Y3b5WmqbUeNeWuLQlkLEa4A8+cgFZU=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd openpam-${version}

            # The release configures OPENPAM_MODULES_DIR, while the runtime
            # lookup checks the older OPENPAM_MODULES_DIRECTORY spelling.
            # Keep the installed modules in the hermetic package closure.
            sed -i 's/OPENPAM_MODULES_DIRECTORY/OPENPAM_MODULES_DIR/g' \
              lib/libpam/openpam_constants.c
          '';
        }
      ]
      ++ (
        if stdenv.isCross && stdenv.hostPlatform.isDarwin
        then [
          {
            name = "darwin-build-paths";
            script = ''
              export CFLAGS="$CFLAGS \
                -ffile-prefix-map=$PWD=. \
                -fdebug-prefix-map=$PWD=."
            '';
          }
        ]
        else []
      )
      ++ [
        {
          name = "configure";
          script = ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --with-localbase=$out \
              --with-modules-dir=$out/lib/security
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
          '';
        }
      ];

    meta = {
      description = "Portable Pluggable Authentication Modules implementation";
      homepage = "https://openpam.org/";
      license = "BSD-3-Clause";
    };
  }
