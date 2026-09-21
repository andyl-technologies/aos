##! setuptools — Python build system and package installer
{
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "84.0.0";
in
  mkDerivation {
    pname = "setuptools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.pythonhosted.org/packages/source/s/setuptools/setuptools-${version}.tar.gz"
      ];
      hash = "sha256-9GlcISV/DZtTfsJpLJQdAu4UO3zBJ2lBNJpUZXOy73M=";
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
          # Setuptools is pure Python. Copy its source package and complete
          # entry-point metadata directly so it can bootstrap PEP 517 builds
          # without first requiring another Python build backend.
          SITE=$out/lib/python3.14/site-packages
          mkdir -p $SITE

          cp -r setuptools $SITE/
          cp -r _distutils_hack $SITE/

          # Install the distutils hack .pth file so that importing setuptools
          # automatically provides a distutils compatibility shim
          printf 'import _distutils_hack; _distutils_hack.do_override()\n' \
            > $SITE/distutils-precedence.pth

          metadata=$SITE/setuptools-${version}.dist-info
          cp -r setuptools.egg-info "$metadata"
          mv "$metadata/PKG-INFO" "$metadata/METADATA"
          touch "$metadata/INSTALLER"
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH=$out/lib/python3.14/site-packages python3 - <<'PY'
          import importlib.metadata
          import setuptools

          assert setuptools.__version__ == "${version}"
          commands = importlib.metadata.entry_points(group="distutils.commands")
          assert any(command.name == "editable_wheel" for command in commands)
          PY
        '';
      }
    ];

    meta = {
      description = "Python build system and package installer";
      homepage = "https://setuptools.pypa.io/";
      license = "MIT";
    };
  }
