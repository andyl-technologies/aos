##! python3-lxml — Python bindings for libxml2 and libxslt
{
  mkDerivation,
  fetchurl,
  python3,
  setuptools,
  cython,
  pkg-config,
  libxml2,
  libxslt,
  zlib,
  buildPackages,
  stdenv,
  lib,
}: let
  version = "6.0.2";
  sitePackages = "lib/python3.14/site-packages";
  pythonForBuild =
    if stdenv.isCross
    then buildPackages.python3
    else python3;
  setuptoolsForBuild =
    if stdenv.isCross
    then buildPackages.setuptools
    else setuptools;
  cythonForBuild =
    if stdenv.isCross
    then buildPackages.cython
    else cython;
  targetPythonPlatform =
    if stdenv.hostPlatform.isDarwin
    then "macosx-13.5-${
      if stdenv.hostPlatform.isAarch64
      then "arm64"
      else "x86_64"
    }"
    else "linux-${stdenv.hostPlatform.parsed.cpu.name}";
  pythonCommand =
    "${pythonForBuild}/bin/python3"
    + lib.optionalString stdenv.isCross " .aos-python-for-target.py";
  pythonEnvironment = ''
    export PYTHONPATH=${setuptoolsForBuild}/${sitePackages}:${cythonForBuild}/${sitePackages}
  '';
in
  mkDerivation {
    pname = "python3-lxml";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/lxml/lxml/archive/refs/tags/lxml-${version}.tar.gz"];
      hash = "sha256-IfKTH8GqPCbyyqQHQundSR08No8c7sPDQZKav/MCNTU=";
    };

    buildDeps = [pythonForBuild setuptoolsForBuild cythonForBuild pkg-config];
    runtimeDeps = [python3 libxml2 libxslt zlib];
    propagatedDeps = [python3 libxml2 libxslt zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd lxml-lxml-${version}
        '';
      }
      {
        name = "patch";
        script =
          ''
            sed -i 's/Cython>=3.1.4/Cython/' pyproject.toml
          ''
          + lib.optionalString stdenv.isCross ''
            # Select system libraries from target Python metadata; the native
            # backend's sys.platform would incorrectly add Linux's librt on Darwin.
            ${pythonForBuild}/bin/python3 - <<'PY'
            from pathlib import Path

            source = Path("setupinfo.py")
            original = source.read_text()
            condition = "if 'linux' in sys.platform:"
            if original.count(condition) != 1:
                raise RuntimeError("Expected exactly one Linux library selection")
            patched = original.replace("import sys\n", "import sys\nimport sysconfig\n", 1)
            patched = patched.replace(condition, 'if sysconfig.get_config_var("MACHDEP") == "linux":')
            source.write_text(patched)
            PY

            # Execute the backend and Cython natively, while keeping extension
            # headers, linker flags, and the ABI suffix from the target Python.
            cat > .aos-python-for-target.py <<'PY'
            import glob
            import runpy
            import sys
            import sysconfig

            modules = glob.glob("${python3}/lib/python3.14/_sysconfigdata_*.py")
            if len(modules) != 1:
                raise RuntimeError("Expected exactly one target Python sysconfig module")

            configuration = sysconfig.get_config_vars()
            native_prefixes = {name: configuration[name] for name in ("prefix", "exec_prefix")}
            configuration.update(runpy.run_path(modules[0])["build_time_vars"])
            # Python 3.14 invalidates its cache when interpreter prefixes
            # change. Keep those identity fields native while all extension
            # build variables and installation bases describe the target.
            configuration.update(native_prefixes)
            for name in ("base", "platbase", "installed_base", "installed_platbase"):
                configuration[name] = "${python3}"

            sys.argv = sys.argv[1:]
            runpy.run_path(sys.argv[0], run_name="__main__")
            PY
            export CFLAGS="-I${python3}/include/python3.14 ''${CFLAGS:-}"
            export _PYTHON_HOST_PLATFORM=${targetPythonPlatform}
          '';
      }
      {
        name = "build";
        script =
          pythonEnvironment
          + ''
            ${pythonCommand} setup.py build --with-cython
          '';
      }
      {
        name = "install";
        script =
          pythonEnvironment
          + ''
            ${pythonCommand} setup.py install --prefix="$out"
          ''
          + lib.optionalString (!stdenv.isCross) ''
            PYTHONPATH="$out/${sitePackages}" ${python3}/bin/python3 -c \
              'from lxml import etree; assert etree.fromstring(b"<a/>").tag == "a"'
          ''
          + lib.optionalString stdenv.isCross ''
            # Foreign extension modules cannot execute here. Verify the full
            # installed extension inventory against CPython's target ABI.
            ${pythonForBuild}/bin/python3 - "$out/${sitePackages}" <<'PY'
            import glob
            from pathlib import Path
            import runpy
            import sys

            modules = glob.glob("${python3}/lib/python3.14/_sysconfigdata_*.py")
            if len(modules) != 1:
                raise RuntimeError("Expected exactly one target Python sysconfig module")
            suffix = runpy.run_path(modules[0])["build_time_vars"]["EXT_SUFFIX"]
            root = Path(sys.argv[1]) / "lxml"
            for module in ("etree", "objectify", "html/diff", "html/_difflib"):
                if not (root / (module + suffix)).is_file():
                    raise RuntimeError(f"Missing target Python extension: {module}{suffix}")
            PY
          '';
      }
    ];

    meta = {
      description = "Pythonic binding for libxml2 and libxslt";
      homepage = "https://lxml.de/";
      license = "BSD-3-Clause";
    };
  }
