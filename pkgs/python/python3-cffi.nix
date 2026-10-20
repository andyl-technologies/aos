##! python3-cffi — Foreign-function interface for Python
{
  mkDerivation,
  fetchurl,
  buildPackages,
  python3,
  pkg-config,
  libffi,
  python3-pycparser,
  stdenv,
  lib,
}: let
  version = "2.1.1";
  sitePackages = "lib/python3.14/site-packages";
  pythonPath = "${buildPackages.setuptools}/${sitePackages}:${buildPackages.python3-pycparser}/${sitePackages}";

  # Darwin extension modules are Mach-O bundles that resolve the Python C API
  # from the loading interpreter, as the target sysconfig LDSHARED does.
  extensionLinker =
    if stdenv.hostPlatform.isDarwin
    then "$CC -bundle -Wl,-undefined,dynamic_lookup"
    else "$CC -shared";

  # Run setuptools with the builder's Python, but take the extension ABI
  # metadata and headers from the target interpreter. The exports persist
  # into the install phase, which reuses the same build directory.
  targetPythonEnvironment = lib.optionalString stdenv.isCross ''
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
    export CPPFLAGS="''${CPPFLAGS:-} -I${python3}/include/python3.14"
    export LDSHARED="${extensionLinker}"
  '';

  # A foreign extension cannot be imported on the builder; check that the
  # backend was installed under the target interpreter's ABI suffix instead.
  installCheck =
    if stdenv.isCross
    then ''
      suffix=$(
        ${buildPackages.python3}/bin/python3 -c \
          'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))'
      )
      test -f "$out/${sitePackages}/_cffi_backend$suffix"
    ''
    else ''

      PYTHONPATH="$out/${sitePackages}:${python3-pycparser}/${sitePackages}" \
        ${python3}/bin/python3 -c \
          'from cffi import FFI; assert FFI().typeof("int").cname == "int"'
    '';
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
      target = [
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
      role = "public-package";
    };

    pname = "python3-cffi";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.pythonhosted.org/packages/source/c/cffi/cffi-${version}.tar.gz"
      ];
      hash = "sha256-3TH1LqEIZRO7nfMPj87puJGDI64Gej1beLyCagAHEr4=";
    };

    buildDeps = [buildPackages.python3 buildPackages.setuptools pkg-config];
    runtimeDeps = [python3 libffi python3-pycparser];
    propagatedDeps = [python3 libffi python3-pycparser];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cffi-${version}
        '';
      }
      {
        name = "build";
        script =
          targetPythonEnvironment
          + ''
            # Setuptools 75 predates the string form of PEP 639 licenses.
            sed -i 's/license = "MIT-0"/license = { text = "MIT-0" }/' pyproject.toml
            sed -i '/^license-files =/d' pyproject.toml

            export PYTHONPATH=${pythonPath}
            ${buildPackages.python3}/bin/python3 setup.py build
          '';
      }
      {
        name = "install";
        script =
          ''
            export PYTHONPATH=${pythonPath}
            ${buildPackages.python3}/bin/python3 setup.py install --prefix="$out"
          ''
          + installCheck;
      }
    ];

    meta = {
      description = "Foreign-function interface for calling C code from Python";
      homepage = "https://cffi.readthedocs.io/";
      license = "MIT-0";
    };
  }
