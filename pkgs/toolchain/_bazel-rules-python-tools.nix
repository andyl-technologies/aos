##! Binds Python rule launchers to the source-built AOS execution interpreter.
{buildPackages}: {
  source,
  python,
}:
buildPackages.mkDerivation {
  pname = "bazel-rules-python-tools";
  version = "1";
  src = source;
  buildDeps = [buildPackages.python3];
  runtimeDeps = [];

  phases = [
    {
      name = "unpack";
      script = ''
        cp -a "$src" rules-python
        chmod -R u+w rules-python
        cd rules-python
      '';
    }
    {
      name = "build";
      script = ''
        # Module overrides bypass the vendor directory's path substitutions.
        # Bind generated py_binary shebangs in the actual rule source instead.
        ${buildPackages.python3}/bin/python3 - '${python}/bin/python3' <<'PY'
        import pathlib
        import sys

        interpreter = sys.argv[1]
        replacements = 0
        for path in pathlib.Path("python").rglob("*"):
            if not path.is_file() or path.suffix not in {".bzl", ".py", ".sh", ".tpl", ".txt"}:
                continue
            original = path.read_text()
            updated = original.replace("#!/usr/bin/env python3", "#!" + interpreter)
            if updated != original:
                path.write_text(updated)
                replacements += 1

        if replacements == 0:
            raise SystemExit("Python rule launcher declarations were not found")
        PY
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out"
        cp -a . "$out/"
      '';
    }
  ];
}
