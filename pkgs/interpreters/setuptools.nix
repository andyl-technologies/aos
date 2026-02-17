##! setuptools — Python build system and package installer
{
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "75.8.2";
in
  mkDerivation {
    pname = "setuptools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.pythonhosted.org/packages/source/s/setuptools/setuptools-${version}.tar.gz"
      ];
      hash = "sha256-SIBHOpaeXyPyor42RrLf2Er5AocW05jkYZL4S8NpANI=";
    };

    buildDeps = [
      python3
    ];
    runtimeDeps = [
      python3
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd setuptools-${version}
        '';
      }
      {
        name = "install";
        script = ''
          # Direct copy install — setuptools is pure Python, so we copy
          # the package directories to site-packages. Using setup.py install
          # fails because the byte-compilation subprocess can't find distutils
          # (Python 3.12 removed it, and the shim only works in-process).
          SITE=$out/lib/python3.12/site-packages
          mkdir -p $SITE

          cp -r setuptools $SITE/
          cp -r pkg_resources $SITE/
          cp -r _distutils_hack $SITE/

          # Install the distutils hack .pth file so that importing setuptools
          # automatically provides a distutils compatibility shim
          printf 'import _distutils_hack; _distutils_hack.do_override()\n' \
            > $SITE/distutils-precedence.pth

          # Write metadata so other packages can find setuptools
          mkdir -p $SITE/setuptools-${version}.dist-info
          printf 'Metadata-Version: 2.1\nName: setuptools\nVersion: ${version}\n' \
            > $SITE/setuptools-${version}.dist-info/METADATA
          printf 'setuptools\npkg_resources\n_distutils_hack\n' \
            > $SITE/setuptools-${version}.dist-info/top_level.txt
          touch $SITE/setuptools-${version}.dist-info/INSTALLER
        '';
      }
    ];

    meta = {
      description = "Python build system and package installer";
      homepage = "https://setuptools.pypa.io/";
      license = "MIT";
    };
  }
