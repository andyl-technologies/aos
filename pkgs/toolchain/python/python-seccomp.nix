##! Python bindings for Linux seccomp filters.
{
  lib,
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
  qualification.packageProbe = lib.qualification.commandProbe {
    primary = {
      input = "A filter allowing calls by default with one getpid rule.";
      operation = "Compile and export the rule set through the Python binding.";
      expected = "The binding resolves getpid and produces a nonempty BPF program.";
      files = {};
      artifacts = [];
      steps = [
        {
          argv = [
            "@python@"
            "-c"
            ''
              import seccomp
              import tempfile

              assert seccomp.resolve_syscall(seccomp.Arch.NATIVE, "getpid") >= 0
              rule_set = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
              rule_set.add_rule(seccomp.ERRNO(1), "getpid")
              with tempfile.TemporaryFile() as output:
                  rule_set.export_bpf(output)
                  output.seek(0)
                  program = output.read()
              assert len(program) >= 8 and len(program) % 8 == 0
              print("python-seccomp filter export passed")
            ''
          ];
          exit_code = 0;
          stdout.exact = "python-seccomp filter export passed\n";
          stderr.exact = "";
        }
      ];
    };
    badInput = {
      input = "A rule naming a nonexistent syscall.";
      operation = "Add the rule to a filter.";
      expected = "The binding rejects the unknown syscall.";
      files = {};
      artifacts = [];
      steps = [
        {
          argv = [
            "@python@"
            "-c"
            ''
              import seccomp

              rule_set = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
              try:
                  rule_set.add_rule(seccomp.ERRNO(1), "not_a_syscall")
              except RuntimeError:
                  print("python-seccomp rejected unknown syscall")
                  raise SystemExit(7)
              raise AssertionError("unknown syscall was accepted")
            ''
          ];
          exit_code = 7;
          observes_rejection = true;
          stdout.exact = "python-seccomp rejected unknown syscall\n";
          stderr.exact = "";
        }
      ];
    };
  };
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
