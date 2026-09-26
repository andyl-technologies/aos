##! Python bindings for Linux seccomp filters.
{
  mkDerivation,
  buildPackages,
  python3,
  libseccomp,
}:
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
    ];
    target = [];
    role = "public-package";
  };
  pname = "python-seccomp";
  version = libseccomp.version;
  src = libseccomp.src;

  buildDeps = [buildPackages.python3 buildPackages.cython];
  runtimeDeps = [python3 libseccomp];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf "$src"
        cd libseccomp-${libseccomp.version}/src/python
      '';
    }
    {
      name = "build";
      script = ''
        # Generate C with the build interpreter, then compile against the target
        # Python headers and extension suffix without executing target Python.
        ${buildPackages.cython}/bin/cython -3 seccomp.pyx -o seccomp.c
        extension_suffix=$(${buildPackages.python3}/bin/python3 - <<'PYTHON'
        import glob
        import runpy
        paths = glob.glob("${python3}/lib/python3.14/_sysconfigdata_*.py")
        if len(paths) != 1:
            raise RuntimeError("Expected exactly one target Python sysconfig module")
        print(runpy.run_path(paths[0])["build_time_vars"]["EXT_SUFFIX"])
        PYTHON
        )
        $CC -O2 -fPIC -shared -I${python3}/include/python3.14 \
          seccomp.c -lseccomp -o "seccomp$extension_suffix"
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/lib/python3.14/site-packages" "$out/share/licenses/python-seccomp"
        cp seccomp*.so "$out/lib/python3.14/site-packages/"
        cp ../../LICENSE "$out/share/licenses/python-seccomp/"
      '';
    }
  ];

  meta = {
    description = "Python bindings for libseccomp syscall filters";
    homepage = "https://github.com/seccomp/libseccomp";
    license = "LGPL-2.1-only";
  };
}
