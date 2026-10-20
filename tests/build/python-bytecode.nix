##! Keeps ordinary Python imports from mutating immutable-image store contents.
{pkgs}:
pkgs.mkDerivation {
  pname = "python-bytecode-check";
  version = "0";
  src = null;
  outputChecks = {};
  buildDeps = [pkgs.python3 pkgs.nix pkgs.coreutils];
  phases = [
    {
      name = "check";
      script = ''
        set -eu
        unset PYTHONHOME PYTHONPATH PYTHONOPTIMIZE PYTHONPYCACHEPREFIX PYTHONDONTWRITEBYTECODE
        ${pkgs.coreutils}/bin/cp -a --no-target-directory ${pkgs.python3} python-copy
        ${pkgs.coreutils}/bin/chmod -R u+w python-copy

        # Inspect with the original interpreter so setup cannot refresh caches
        # in the writable copy before the baseline is recorded.
        ${pkgs.python3}/bin/python3 - <<'PY'
        import importlib.util
        import marshal
        import os
        from pathlib import Path
        import struct
        import sysconfig

        root = Path("python-copy").resolve()
        library = root / "lib" / ("python" + sysconfig.get_python_version())
        sources = list(library.rglob("*.py"))
        assert sources, "the actual Python package contains no sources"
        for source in sources:
            os.utime(source, ns=(0, 0))
            # Upstream installs this executable helper after compileall. It
            # runs as a script and is not an imported library module.
            if (
                source.name == "python-config.py"
                and source.parent.parent == library
                and source.parent.name.startswith("config-" + sysconfig.get_python_version() + "-")
            ):
                continue
            for level in (0, 1, 2):
                cache = Path(importlib.util.cache_from_source(
                    str(source), optimization="" if level == 0 else str(level)
                ))
                assert cache.is_file(), f"missing optimization-{level} cache: {source}"

        caches = list(library.rglob("*.pyc"))
        assert caches, "the actual Python package contains no bytecode"
        for cache in caches:
            header = cache.read_bytes()[:16]
            assert len(header) == 16 and header[:4] == importlib.util.MAGIC_NUMBER, cache
            assert struct.unpack("<I", header[4:8])[0] == 1, f"not unchecked-hash: {cache}"

        # Scrubbing sysconfig rewrites source paths. Hash-based caches must
        # contain the rewritten code, rather than merely suppress validation.
        sysconfig_sources = [
            library / "sysconfig" / "__init__.py",
            library / (sysconfig._get_sysconfigdata_name() + ".py"),
        ]
        for source in sysconfig_sources:
            assert source.is_file(), source
            for level in (0, 1, 2):
                cache = Path(importlib.util.cache_from_source(
                    str(source), optimization="" if level == 0 else str(level)
                ))
                cached = marshal.loads(cache.read_bytes()[16:])
                expected = compile(
                    source.read_bytes(), cached.co_filename, "exec",
                    dont_inherit=True, optimize=level,
                )
                assert cached == expected, f"stale sysconfig bytecode: {cache}"
        print(f"Checked {len(sources)} sources and {len(caches)} unchecked-hash caches")
        PY

        cat > check-imports.py <<'PY'
        import _imp
        import email.message
        import importlib
        import json
        from pathlib import Path
        import ssl
        import sys
        import sysconfig
        import jinja2
        import markupsafe

        def require(condition, message):
            if not condition:
                raise AssertionError(message)

        root = Path("python-copy").resolve()
        # Assertions are disabled by -O/-OO; these checks must run at all levels.
        require(Path(sys.prefix).resolve() == root, "interpreter is outside the copy")
        require(not sys.dont_write_bytecode, "bytecode writes are disabled")
        require(sys.pycache_prefix is None, "bytecode is redirected outside the copy")
        require(_imp.check_hash_based_pycs == "default", "hash validation policy changed")
        require(sysconfig.get_config_var("CC"), "selected sysconfig data did not load")
        data = importlib.import_module(sysconfig._get_sysconfigdata_name())
        for module in (email.message, json, ssl, sysconfig, data, jinja2, markupsafe):
            require(Path(module.__file__).resolve().is_relative_to(root), module.__file__)
        rendered = jinja2.Environment(autoescape=True).from_string("{{ value }}").render(
            value="<qualification>"
        )
        require(rendered == "&lt;qualification&gt;", "Jinja2 rendering failed")
        require(str(markupsafe.escape("<qualification>")) == "&lt;qualification&gt;", "MarkupSafe escaping failed")
        print(f"Normal imports passed at optimization level {sys.flags.optimize}")
        PY

        ${pkgs.nix}/bin/nix-store --dump python-copy > before.nar
        for optimization in 0 1 2; do
          PYTHONHOME="$PWD/python-copy" PYTHONOPTIMIZE="$optimization" \
            "$PWD/python-copy/bin/python3" check-imports.py
        done
        ${pkgs.nix}/bin/nix-store --dump python-copy > after.nar
        ${pkgs.python3}/bin/python3 - <<'PY'
        from pathlib import Path

        with Path("before.nar").open("rb") as before, Path("after.nar").open("rb") as after:
            while chunk := before.read(1048576):
                assert chunk == after.read(len(chunk)), "normal imports changed the package NAR"
            assert not after.read(1), "normal imports enlarged the package NAR"
        PY

        # A timestamp cache genuinely becomes stale when image creation sets
        # its source mtime to zero; ordinary import must expose that mutation.
        ${pkgs.python3}/bin/python3 - <<'PY'
        import os
        from pathlib import Path
        import py_compile
        import struct

        source = Path("timestamp-control/qualification_timestamp.py")
        source.parent.mkdir()
        source.write_text("value = 42\n")
        os.utime(source, ns=(17000000000, 17000000000))
        cache = Path(py_compile.compile(
            str(source), doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
        ))
        assert struct.unpack("<I", cache.read_bytes()[4:8])[0] == 0
        os.utime(source, ns=(0, 0))
        PY
        ${pkgs.nix}/bin/nix-store --dump timestamp-control > timestamp-before.nar
        PYTHONHOME="$PWD/python-copy" "$PWD/python-copy/bin/python3" -c \
          'import sys; assert not sys.dont_write_bytecode; sys.path.insert(0, "timestamp-control"); import qualification_timestamp; assert qualification_timestamp.value == 42'
        ${pkgs.nix}/bin/nix-store --dump timestamp-control > timestamp-after.nar
        ${pkgs.python3}/bin/python3 - <<'PY'
        from pathlib import Path

        assert Path("timestamp-before.nar").read_bytes() != Path("timestamp-after.nar").read_bytes(), \
            "timestamp-cache negative control did not mutate"
        PY

        mkdir -p "$out"
        printf '%s\n' PASS > "$out/result"
      '';
    }
  ];
}
