##! Python YAML parser and emitter with the libyaml acceleration module
{
  mkDerivation,
  fetchurl,
  buildPackages,
  python3,
  libyaml,
  stdenv,
  lib,
}: let
  version = "6.0.3";
  sitePackages = "lib/python3.14/site-packages";
  pythonPath = "${buildPackages.setuptools}/${sitePackages}:${buildPackages.cython}/${sitePackages}";
in
  mkDerivation {
    pname = "python3-pyyaml";
    inherit version;

    src = fetchurl {
      urls = ["https://files.pythonhosted.org/packages/source/p/pyyaml/pyyaml-${version}.tar.gz"];
      hash = "sha256-12YjNzQh3yL7TPiBcCDLt+8VxyW51eRfF+GJv8OEGQ8=";
    };

    buildDeps = [buildPackages.python3 buildPackages.setuptools buildPackages.cython];
    runtimeDeps = [python3 libyaml];
    propagatedDeps = [python3 libyaml];
    PYTHONPATH = pythonPath;
    PYYAML_FORCE_CYTHON = "1";

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd pyyaml-${version}
          '';
        }
        {
          name = "build";
          script = ''
            ${lib.optionalString stdenv.isCross ''
              # Generate C with native Python, but use the target interpreter's
              # real ABI metadata and headers when compiling its extension.
              set -- ${python3}/lib/python3.14/_sysconfigdata_*.py
              test "$#" -eq 1 && test -f "$1"
              export _PYTHON_SYSCONFIGDATA_NAME="$(basename "$1" .py)"
              export _PYTHON_SYSCONFIGDATA_PATH=${python3}/lib/python3.14
              export _PYTHON_HOST_PLATFORM=${
                if stdenv.hostPlatform.isDarwin
                then "darwin"
                else "linux"
              }-${
                if stdenv.hostPlatform.isAarch64
                then "aarch64"
                else "x86_64"
              }
              export CPPFLAGS="$CPPFLAGS -I${python3}/include/python3.14"
              export LDSHARED="$CC -shared"
            ''}
            ${buildPackages.python3}/bin/python3 setup.py --with-libyaml build
          '';
        }
        {
          name = "install";
          script = ''
            ${buildPackages.python3}/bin/python3 setup.py --with-libyaml install --prefix="$out"
            mkdir -p "$out/share/licenses/python3-pyyaml"
            cp LICENSE "$out/share/licenses/python3-pyyaml/"
          '';
        }
      ]
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            PYTHONPATH="$out/${sitePackages}" \
              ${buildPackages.python3}/bin/python3 -c \
              'import yaml; assert yaml.__with_libyaml__; assert yaml.load("graphics: true", Loader=yaml.CSafeLoader) == {"graphics": True}'
          '';
        }
      ];

    meta = {
      description = "YAML parser and emitter for Python, accelerated by libyaml";
      homepage = "https://pyyaml.org/";
      license = "MIT";
    };
  }
