##! X protocol C-language binding with generated extension APIs.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  libxau,
  libxdmcp,
  check,
  withDocs ? true,
  packageName ? "libxcb",
}: let
  version = "1.17.0";
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
    pname = packageName;
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libxcb-${version}.tar.xz"];
      hash = "0mbdkajqhg0j0zjc9a2z1qyv9mca797ihvifc9qyl3vijscvz7jr";
    };
    buildDeps =
      [buildPackages.gnumake buildPackages.pkg-config buildPackages.python3 buildPackages.xcb-proto buildPackages.libxslt]
      ++ (
        if withDocs
        then [buildPackages.doxygen buildPackages.graphviz]
        else []
      );
    runtimeDeps = [libxau libxdmcp check];
    propagatedDeps = [libxau libxdmcp];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libxcb-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            export PYTHON=${buildPackages.python3}/bin/python3
            export PKG_CONFIG_PATH="${buildPackages.xcb-proto}/lib/pkgconfig:$PKG_CONFIG_PATH"
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out" --enable-shared --enable-static ${
              if withDocs
              then "--enable-devel-docs --with-doxygen"
              else "--disable-devel-docs --without-doxygen"
            }
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES"
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
              make check
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make install
            mkdir -p "$out/share/licenses/libxcb"
            cp COPYING "$out/share/licenses/libxcb/"
          '';
        }
      ];
    meta = {
      description = "X protocol C-language binding";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
