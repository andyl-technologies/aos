"""Compare compiler behavior with direct execution and pinned sccache.

Every fixture uses identical compiler paths, arguments, environment, working
and output directories for all three implementations. Output inventories are
observed independently of accache's declarations, so a missing side artifact
cannot make the test pass. Warm runs remove every generated artifact first.
The private sccache server is bounded by this process and stopped in finally.
"""

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


@dataclass
class Fixture:
    """Describe a deterministic invocation and optional input mutation."""

    name: str
    compiler: str
    arguments: list[str]
    sources: dict[str, str]
    changes: dict[str, str] = field(default_factory=dict)
    cacheable: bool = True
    exit_code: int = 0
    precompile: list[str] = field(default_factory=list)
    nondeterministic_outputs: set[str] = field(default_factory=set)
    direct_exit_code: int | None = None


def fixtures(gcc, clang, rustc):
    """Exercise parser families, artifact families, and unchanged bypasses."""
    c_sources = {
        "source.c": '#include "value.h"\nint answer(void) { return VALUE; }\n',
        "value.h": "#define VALUE 42\n",
    }
    for name, compiler in [("gcc", gcc), ("clang", clang)]:
        base = ["-c", "source.c", "-o", "source.o"]
        for suffix, flags in [
            ("ordinary", []),
            ("optimization", ["-O3", "-march=x86-64", "-mtune=generic", "-fno-math-errno"]),
            ("debug", ["-g", "-gdwarf-4", "-fdebug-prefix-map=/build=/source"]),
            ("split-debug", ["-g", "-gsplit-dwarf"]),
            ("optional-split-debug", ["-gsplit-dwarf"]),
            ("coverage", ["--coverage"]),
            ("profile-generation", ["-fprofile-generate"]),
            ("depfile", ["-MD", "-MF", "source.d", "-MT", "custom-target"]),
            ("default-depfile", ["-MMD", "-MP"]),
            ("include", ["-include", "value.h", "-I.", "-isystem", "."]),
            ("defines", ["-DUNUSED=123", "-UUNUSED", "-fPIC", "-fvisibility=hidden"]),
            ("lto", ["-flto"]),
            ("address-sanitizer", ["-fsanitize=address"]),
            ("openmp", ["-fopenmp"]),
            ("stack-protector", ["-fstack-protector-strong"]),
        ]:
            # Give independent cases distinct compiler identities. Otherwise
            # sccache can reuse an earlier object-only entry for a depfile case,
            # then fall back on its next direct-mode lookup (no stored .d).
            yield Fixture(name + "-" + suffix, compiler,
                          base + flags + ["-frandom-seed=" + name + "-" + suffix], c_sources,
                          {"value.h": "#define VALUE 73\n"})

        yield Fixture(name + "-stack-usage", compiler,
                      base + ["-fstack-usage"], c_sources,
                      {"value.h": "#define VALUE 73\n"}, cacheable=False)
        if name == "gcc":
            yield Fixture("gcc-aux-info", compiler,
                          base + ["-aux-info", "source.aux"], c_sources,
                          {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-tree-dump", compiler,
                          base + ["-fdump-tree-original"], c_sources,
                          {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-multiple-dumps", compiler,
                          base + ["-fdump-tree-original", "-fdump-rtl-expand"], c_sources,
                          {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-tree-all-dumps", compiler,
                          base + ["-O2", "-fdump-tree-all"], c_sources,
                          {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-statistics-dump", compiler,
                          base + ["-O2", "-fdump-statistics-stats"], c_sources,
                          {"value.h": "#define VALUE 73\n"})
            for stream in ["stdout", "stderr"]:
                yield Fixture(f"gcc-tree-dump-{stream}", compiler,
                              base + [f"-fdump-tree-original={stream}"], c_sources,
                              {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-explicit-tree-dump", compiler,
                          base + ["-fdump-tree-original=report.txt"], c_sources,
                          {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-opt-report", compiler,
                          base + ["-O2", "-fopt-info-optimized=report.txt"],
                          {"source.c": ('#include "value.h"\n'
                                        'static inline int square(int x) { return x * x; }\n'
                                        'int answer(void) { return square(VALUE); }\n'),
                           "value.h": "#define VALUE 42\n"},
                          {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-sarif-report", compiler,
                          base + ["-fdiagnostics-format=sarif-file"], c_sources,
                          {"value.h": "#define VALUE 73\n"},
                          nondeterministic_outputs={"source.c.sarif"})
            yield Fixture("gcc-sarif-nested-output", compiler,
                          ["-c", "source.c", "-o", "objects/source.c.o",
                           "-fdiagnostics-format=sarif-file"],
                          c_sources | {"objects/.keep": ""},
                          nondeterministic_outputs={"objects/source.c.c.sarif"})
        else:
            yield Fixture("clang-serialized-diagnostics", compiler,
                          base + ["--serialize-diagnostics", "source.dia"], c_sources,
                          {"value.h": "#define VALUE 73\n"})
        yield Fixture(name + "-default-output", compiler, ["-c", "source.c"], c_sources)
        yield Fixture(name + "-joined-output", compiler, ["-c", "source.c", "-osource.o"], c_sources)
        yield Fixture(name + "-response", compiler, ["@arguments.rsp"], c_sources | {
            "arguments.rsp": '-c source.c @nested.rsp -o "source output.o"\n',
            "nested.rsp": '-O2 -D"UNUSED=7"\n',
        }, {"nested.rsp": "-O3 -DUNUSED=8\n"})
        yield Fixture(name + "-spaced-dependencies", compiler,
                      ["-c", "source with space.c", "-MMD", "-MF", "source.d",
                       "-o", "source.o"],
                      {"source with space.c": '#include "header with space.h"\nint answer(void) { return VALUE; }\n',
                       "header with space.h": "#define VALUE 42\n"},
                      {"header with space.h": "#define VALUE 73\n"})
        yield Fixture(name + "-cplusplus", compiler,
                      ["-c", "source.cc", "-std=c++20", "-O2", "-o", "source.o"],
                      {"source.cc": "template<int N> struct V { static constexpr int value = N; }; int answer() { return V<42>::value; }\n"})
        yield Fixture(name + "-warnings", compiler, base + ["-Wall", "-Wextra", "-fdiagnostics-color=always"],
                      {"source.c": "int answer(int unused) { return 42; }\n"})
        yield Fixture(name + "-preprocessed", compiler, ["-c", "source.i", "-o", "source.o"],
                      {"source.i": "int answer(void) { return 42; }\n"})
        # sccache forces this color option internally; supplying it explicitly
        # makes Clang's unused-option diagnostic identical in all three runs.
        yield Fixture(name + "-assembly", compiler,
                      ["-c", "source.s", "-o", "source.o", "-fdiagnostics-color=always"],
                      {"source.s": ".text\n.globl answer\nanswer:\n.byte 0xc3\n"})
        yield Fixture(name + "-assembly-cpp", compiler, ["-c", "source.S", "-o", "source.o"],
                      {"source.S": '#include "value.h"\n.text\n.globl answer\nanswer:\n.byte VALUE\n',
                       "value.h": "#define VALUE 0xc3\n"})
        yield Fixture(name + "-assembly-include", compiler,
                      ["-c", "source.S", "-I.", "-o", "source.o"],
                      {"source.S": '.text\n.globl answer\nanswer:\n.include "fragment.inc"\n',
                       "fragment.inc": ".byte 0xc3\n"})
        yield Fixture(name + "-failed", compiler, base,
                      {"source.c": "#error intentional oracle failure\n"}, cacheable=False, exit_code=1)
        yield Fixture(name + "-preprocess-only", compiler, ["-E", "source.c"], c_sources, cacheable=False)
        yield Fixture(name + "-unknown-invalid", compiler, base + ["-faccache-intentionally-invalid"],
                      c_sources, cacheable=False, exit_code=1)

    for extension, language in [("m", "objc"), ("mm", "objcxx"),
                                ("mi", "objc-preprocessed"), ("mii", "objcxx-preprocessed")]:
        yield Fixture("clang-" + language, clang,
                      ["-c", "source." + extension, "-o", "source.o"],
                      {"source." + extension: "int answer(void) { return 42; }\n"},
                      {"source." + extension: "int answer(void) { return 73; }\n"})

    # PCH/PCM serialize diagnostic configuration. Use sccache's forced color
    # setting explicitly so the reference compiler serializes the same options.
    yield Fixture("clang-pch", clang, ["-x", "c-header", "-c", "header.h", "-o", "header.pch", "-fdiagnostics-color=always"],
                  {"header.h": "#define VALUE 42\n"})
    yield Fixture("clang-xclang-pch", clang,
                  ["-x", "c-header", "-Xclang", "-emit-pch", "-c", "header.h",
                   "-o", "header.pch", "-fdiagnostics-color=always"],
                  {"header.h": "#define VALUE 42\n"},
                  {"header.h": "#define VALUE 73\n"})
    for name, compiler, precompiled, include in [
        ("gcc", gcc, "header.h.gch", []),
        ("clang", clang, "header.pch", ["-include-pch", "header.pch"]),
    ]:
        yield Fixture(name + "-pch-consumer", compiler,
                      ["-c", "consumer.c", "-o", "consumer.o", *include,
                       "-fdiagnostics-color=always"],
                      {"header.h": "#define VALUE 42\n",
                       "consumer.c": '#include "header.h"\nint answer(void) { return VALUE + 1; }\n'},
                      {"consumer.c": '#include "header.h"\nint answer(void) { return VALUE + 2; }\n'},
                      precompile=["-x", "c-header", "-c", "header.h", "-o", precompiled,
                                  "-fdiagnostics-color=always"])
    yield Fixture("gcc-pch", gcc,
                  ["-x", "c-header", "-c", "header.h", "-o", "header.h.gch",
                   "-fdiagnostics-color=always"],
                  {"header.h": "#define VALUE 42\n"},
                  nondeterministic_outputs={"header.h.gch"})
    yield Fixture("clang-module", clang,
                  ["-std=c++20", "-c", "--precompile", "module.cppm", "-o", "example.pcm", "-fdiagnostics-color=always"],
                  {"module.cppm": "export module example; export int answer() { return 42; }\n"})
    yield Fixture("clang-module-side-output", clang,
                  ["-std=c++20", "-c", "module.cppm", "-fmodule-output=example.pcm", "-o", "module.o", "-fdiagnostics-color=always"],
                  {"module.cppm": "export module example; export int answer() { return 42; }\n"})

    rust_sources = {"library.rs": 'pub fn answer() -> &\'static str { include_str!("value.txt") }\n', "value.txt": "first"}
    for name, flags in [
        ("rlib", ["--emit=link,dep-info"]),
        ("metadata", ["--emit=metadata,dep-info"]),
        ("all-outputs", ["--emit=link,metadata,dep-info"]),
        ("optimized", ["--emit=link,dep-info", "-Copt-level=3", "--codegen=target-cpu=x86-64", "-Ctarget-feature=+sse2"]),
        ("debug", ["--emit=link,dep-info", "-Cdebuginfo=2", "-Csplit-debuginfo=packed"]),
        ("diagnostics", ["--emit=link,dep-info", "--error-format=json", "--json=diagnostic-rendered-ansi,artifacts"]),
        ("extra-filename", ["--emit=link,dep-info", "-Cextra-filename=-abc123"]),
        ("metadata-disambiguator", ["--emit=link,dep-info", "-C", "metadata=oracle123"]),
        ("panic-abort", ["--emit=link,dep-info", "-Cpanic=abort"]),
        ("multiple-codegen-units", ["--emit=link,dep-info", "-C", "codegen-units=4"]),
        ("cfg-check", ["--emit=link,dep-info", '--cfg=feature="oracle"',
                       '--check-cfg=cfg(feature, values("oracle"))']),
    ]:
        yield Fixture("rust-" + name, rustc,
                      ["--crate-name=example", "--crate-type=rlib", "--out-dir=target", "library.rs", *flags],
                      rust_sources, {"value.txt": "second"})
    yield Fixture("rust-staticlib", rustc,
                  ["--crate-name=example", "--crate-type=staticlib", "--emit=link,dep-info", "--out-dir=target", "library.rs"],
                  rust_sources)
    for name, crate_type, emits in [
        ("rlib-metadata-only", "rlib", "metadata,dep-info"),
        ("staticlib-metadata-only", "staticlib", "metadata,dep-info"),
        ("staticlib-all-outputs", "staticlib", "link,metadata,dep-info"),
        ("rlib-staticlib", "rlib,staticlib", "link,metadata,dep-info"),
        ("rlib-link-only", "rlib", "link"),
    ]:
        yield Fixture("rust-" + name, rustc,
                      ["--crate-name=example", "--crate-type=" + crate_type,
                       "--out-dir=target", "library.rs", "--emit=" + emits],
                      rust_sources, {"value.txt": "second"})
    yield Fixture("rust-response", rustc, ["@arguments.rsp"], rust_sources | {
        "arguments.rsp": "--crate-name=example\n--crate-type=rlib\n--emit=link,dep-info\n--out-dir=target\nlibrary.rs\n",
    })
    yield Fixture("rust-nested-response", rustc, ["@outer.rsp"], rust_sources | {
        "outer.rsp": "--crate-name=example\n--crate-type=rlib\n--emit=link,dep-info\n--out-dir=target\n@inner.rsp\nlibrary.rs\n",
        "inner.rsp": "-Copt-level=0\n",
    }, {"inner.rsp": "-Copt-level=3\n"}, direct_exit_code=1)
    yield Fixture("rust-failed", rustc,
                  ["--crate-type=rlib", "--emit=link,dep-info", "--out-dir=target", "library.rs"],
                  {"library.rs": 'compile_error!("intentional oracle failure");\n'}, cacheable=False, exit_code=1)
    yield Fixture("rust-proc-macro-consumer", rustc,
                  ["--crate-name=macro_user", "--crate-type=rlib", "--emit=link,dep-info",
                   "--out-dir=target", "--extern", "numbers=libnumbers.so", "library.rs"],
                  {"macro.rs": 'extern crate proc_macro; use proc_macro::TokenStream; #[proc_macro] pub fn number(_: TokenStream) -> TokenStream { "42".parse().unwrap() }\n',
                   "library.rs": "extern crate numbers; pub const ANSWER: u32 = numbers::number!();\n"},
                  precompile=["--crate-name=numbers", "--crate-type=proc-macro", "macro.rs",
                              "-o", "libnumbers.so"])
    yield Fixture("rust-query", rustc, ["--version", "--verbose"], {}, cacheable=False)


def snapshot(work):
    """Observe file contents and executable bits without relying on a parser."""
    return {str(path.relative_to(work)): (path.read_bytes(), bool(path.stat().st_mode & 0o111))
            for path in work.rglob("*") if path.is_file()}


def check_saved_temporaries(root, env, accache, sccache, rustc, hits):
    """Check that requested Rust temporary outputs survive accache invocations."""
    # Pinned sccache caches -Csave-temps but drops its dynamically named
    # bitcode and temporary metadata on a hit. Accache preserves these
    # requested outputs by letting rustc compile instead of caching it.
    save_temps = root / "rust-save-temps"
    save_temps.mkdir()
    (save_temps / "target").mkdir()
    (save_temps / "library.rs").write_text("pub fn answer() -> u32 { 42 }\n")
    save_args = [rustc, "--crate-name=example", "--crate-type=rlib",
                 "--emit=link,dep-info", "--out-dir=target", "library.rs",
                 "-Csave-temps=yes"]

    def compile_with_saved_temporaries(wrapper):
        for path in (save_temps / "target").rglob("*"):
            if path.is_file():
                path.unlink()
        completed = subprocess.run([*wrapper, *save_args], cwd=save_temps,
                                   env=env, capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        files = snapshot(save_temps)
        files.pop("library.rs")
        return files

    def saved_bitcode(files):
        return any(name.endswith(".bc") for name in files)

    direct_saved = compile_with_saved_temporaries([])
    oracle_saved = compile_with_saved_temporaries([sccache])
    before_hits = hits()
    oracle_hit_saved = compile_with_saved_temporaries([sccache])
    assert hits() > before_hits, "sccache did not hit save-temps action"
    accache_saved = compile_with_saved_temporaries([accache])
    cold_saved_event = json.loads(subprocess.check_output([accache, "explain"], env=env))
    accache_warm_saved = compile_with_saved_temporaries([accache])
    warm_saved_event = json.loads(subprocess.check_output([accache, "explain"], env=env))

    for name in ["target/example.d", "target/libexample.rlib"]:
        assert len({files[name] for files in [direct_saved, oracle_saved,
                                                oracle_hit_saved, accache_saved,
                                                accache_warm_saved]}) == 1, name
    assert all(saved_bitcode(files) for files in [direct_saved, oracle_saved,
                                                   accache_saved, accache_warm_saved])
    assert not saved_bitcode(oracle_hit_saved), "sccache save-temps defect changed"
    for event in [cold_saved_event, warm_saved_event]:
        assert event["outcome"] == "bypass" and "save-temps" in event["reason"], event
    print("PASS oracle rust-save-temps output preservation", flush=True)
    return {"fixture": "rust-save-temps", "revision": 0,
            "oracle_hit": True, "accache": "bypass",
            "oracle_missing_artifacts": sorted(set(oracle_saved) - set(oracle_hit_saved)),
            "artifacts": sorted(direct_saved)}


def check_assembler_include_invalidation(root, env, accache, sccache, gcc, hits):
    """Require a miss when a GNU assembler .include changes beneath .S."""
    work = root / "gcc-assembler-include-mutation"
    work.mkdir()
    (work / "source.S").write_text(
        '.text\n.globl answer\nanswer:\n.include "fragment.inc"\n')
    included = work / "fragment.inc"
    included.write_text(".byte 0xc3\n")
    object_file = work / "source.o"
    args = [gcc, "-c", "source.S", "-I.", "-o", "source.o"]

    def compile_object(wrapper):
        object_file.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return object_file.read_bytes()

    direct_old = compile_object([])
    assert compile_object([accache]) == direct_old
    assert compile_object([sccache]) == direct_old

    included.write_text(".byte 0x90\n")
    direct_new = compile_object([])
    assert direct_new != direct_old, "assembler include mutation changed no output"
    before_hits = hits()
    assert compile_object([sccache]) == direct_old, "sccache defect changed"
    assert hits() > before_hits, "sccache did not reuse the stale action"

    assert compile_object([accache]) == direct_new
    changed = json.loads(subprocess.check_output([accache, "explain"], env=env))
    assert changed["outcome"] == "miss", changed
    assert any("fragment.inc" in item for item in changed["changes"]), changed
    assert compile_object([accache]) == direct_new
    warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
    assert warm["outcome"] == "hit", warm

    print("PASS oracle GNU assembler include invalidation", flush=True)
    return {"fixture": "gcc-assembler-include-invalidation", "revision": 1,
            "oracle_hit": True, "accache": "hit",
            "oracle_stale_artifact": "source.o", "artifacts": ["source.o"]}


def check_field_named_include(root, env, accache, sccache, gcc, clang, hits):
    """A C field named include must not trigger an assembler dependency probe."""
    results = []
    for name, compiler in [("gcc", gcc), ("clang", clang)]:
        fixture = f"{name}-absolute-field-include"
        work = root / fixture
        source_dir = work / "src"
        build_dir = work / "build"
        source_dir.mkdir(parents=True)
        build_dir.mkdir()
        source = source_dir / "source.c"
        source.write_text("struct section { int include; };\n"
                          "int answer(void) { struct section value = {42}; return value.include; }\n")
        output = build_dir / "source.o"
        args = [compiler, "-g", "-c", str(source), "-o", "source.o"]

        def compile_object(wrapper):
            output.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=build_dir, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return output.read_bytes()

        direct = compile_object([])
        assert compile_object([sccache]) == direct
        before_hits = hits()
        assert compile_object([sccache]) == direct
        assert hits() > before_hits, (fixture, "sccache did not hit")

        assert compile_object([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", (fixture, cold)
        assert compile_object([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", (fixture, warm)
        results.append({"fixture": fixture, "revision": 0,
                        "oracle_hit": True, "accache": "hit", "artifacts": ["build/source.o"]})
        print("PASS oracle", fixture, flush=True)
    return results


def check_absolute_inline_assembler_input(root, env, accache, sccache, gcc, hits):
    """Track an assembler file read from an absolute-path CMake-style source."""
    work = root / "gcc-absolute-inline-asm"
    source_dir = work / "src"
    build_dir = work / "build"
    source_dir.mkdir(parents=True)
    build_dir.mkdir()
    source = source_dir / "source.c"
    source.write_text('asm(".text\\n.globl embedded\\nembedded:\\n.incbin \\"fragment.bin\\"\\n");\n')
    fragment = build_dir / "fragment.bin"
    fragment.write_bytes(b"one")
    output = build_dir / "source.o"
    args = [gcc, "-c", str(source), "-o", "source.o"]

    def compile_object(wrapper):
        output.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=build_dir, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return output.read_bytes()

    direct_old = compile_object([])
    assert compile_object([sccache]) == direct_old
    assert compile_object([accache]) == direct_old
    cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
    assert cold["outcome"] == "miss", cold
    assert compile_object([accache]) == direct_old
    warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
    assert warm["outcome"] == "hit", warm

    fragment.write_bytes(b"two")
    direct_new = compile_object([])
    assert direct_new != direct_old, "assembler input changed no object bytes"
    before_hits = hits()
    assert compile_object([sccache]) == direct_old, "sccache defect changed"
    assert hits() > before_hits, "sccache did not reuse the stale action"
    assert compile_object([accache]) == direct_new
    changed = json.loads(subprocess.check_output([accache, "explain"], env=env))
    assert changed["outcome"] == "miss", changed
    assert any("fragment.bin" in item for item in changed["changes"]), changed
    assert compile_object([accache]) == direct_new
    warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
    assert warm["outcome"] == "hit", warm

    print("PASS oracle GCC absolute inline assembler input", flush=True)
    return {"fixture": "gcc-absolute-inline-asm", "revision": 1,
            "oracle_hit": True, "accache": "hit",
            "oracle_stale_artifact": "build/source.o", "artifacts": ["build/source.o"]}


def check_inline_assembler_inputs(root, env, accache, sccache, gcc, clang, hits):
    """Invalidate C and preprocessed C actions when inline assembly reads a file."""
    results = []
    source = 'asm(".text\\n.globl embedded\\nembedded:\\n.incbin \\"fragment.bin\\"\\n");\n'
    for compiler_name, compiler in [("gcc", gcc), ("clang", clang)]:
        for extension in ["c", "i"]:
            fixture = f"{compiler_name}-inline-asm-{extension}"
            work = root / fixture
            work.mkdir()
            (work / f"source.{extension}").write_text(source)
            fragment = work / "fragment.bin"
            output = work / "source.o"
            args = [compiler, "-c", f"source.{extension}", "-o", "source.o"]

            def compile_object(wrapper):
                output.unlink(missing_ok=True)
                completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                           capture_output=True, timeout=120)
                assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
                return completed.stdout, completed.stderr, output.read_bytes()

            old_object = None
            for revision, byte in enumerate([b"\xc3", b"\x90"]):
                fragment.write_bytes(byte)
                direct = compile_object([])
                if revision:
                    assert direct[2] != old_object, fixture
                else:
                    old_object = direct[2]

                before_cold_hits = hits()
                oracle_cold = compile_object([sccache])
                if revision:
                    assert oracle_cold[2] == old_object, "sccache defect changed"
                    assert hits() > before_cold_hits, "sccache did not replay stale object"
                else:
                    assert oracle_cold == direct
                before_warm_hits = hits()
                assert compile_object([sccache]) == oracle_cold
                assert hits() > before_warm_hits

                assert compile_object([accache]) == direct
                cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
                assert cold["outcome"] == "miss", cold
                if revision:
                    assert any("fragment.bin" in item for item in cold["changes"]), cold
                assert compile_object([accache]) == direct
                warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
                assert warm["outcome"] == "hit", warm
                results.append({"fixture": fixture, "revision": revision,
                                "oracle_hit": True, "accache": "hit",
                                "oracle_stale_artifact": "source.o" if revision else None,
                                "artifacts": ["source.o"]})

            print("PASS oracle", fixture, "input invalidation", flush=True)
    return results


def check_clang_profile_use(root, env, accache, sccache, clang, hits):
    """Track the profile data consumed by a cacheable Clang action."""
    work = root / "clang-profile-use"
    work.mkdir()
    (work / "source.c").write_text(
        "int branch(int x) { if (x > 100) return x * 3; return x + 1; }\n"
        "int main(int argc, char **argv) { return branch(argc); }\n")
    subprocess.run([clang, "-O2", "-fprofile-instr-generate", "source.c", "-o", "program"],
                   cwd=work, env=env, check=True, capture_output=True)
    profdata = str(Path(clang).with_name("llvm-profdata"))
    profiles = []
    for name, arguments in [("low", []), ("high", ["x"] * 150)]:
        raw = work / (name + ".profraw")
        subprocess.run([str(work / "program"), *arguments], cwd=work,
                       env=env | {"LLVM_PROFILE_FILE": str(raw)}, capture_output=True,
                       timeout=120)
        merged = work / (name + ".profdata")
        subprocess.run([profdata, "merge", "-o", str(merged), str(raw)], cwd=work,
                       env=env, check=True, capture_output=True)
        profiles.append(merged.read_bytes())
    assert profiles[0] != profiles[1], "profile runs produced identical input data"

    object_file = work / "source.o"
    profile_file = work / "profile.profdata"
    args = [clang, "-O2", "-c", "source.c", "-fprofile-instr-use=profile.profdata",
            "-o", "source.o"]

    def compile_object(wrapper):
        object_file.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return completed.stdout, completed.stderr, object_file.read_bytes()

    results = []
    for revision, profile in enumerate(profiles):
        profile_file.write_bytes(profile)
        direct = compile_object([])
        before_cold_hits = hits()
        assert compile_object([sccache]) == direct
        assert hits() == before_cold_hits, "sccache ignored the changed profile"
        before_hits = hits()
        assert compile_object([sccache]) == direct
        assert hits() > before_hits, "sccache did not hit the profile action"

        assert compile_object([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", cold
        if revision:
            assert any("profile.profdata" in item for item in cold["changes"]), cold
        assert compile_object([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", warm
        results.append({"fixture": "clang-profile-use", "revision": revision,
                        "oracle_hit": True, "accache": "hit", "artifacts": ["source.o"]})

    print("PASS oracle Clang profile input invalidation", flush=True)
    return results


def check_rust_profile_use(root, env, accache, sccache, rustc, clang, hits):
    """Track rustc's profile input across cold and warm library actions."""
    work = root / "rust-profile-use"
    work.mkdir()
    (work / "target").mkdir()
    (work / "source.rs").write_text(
        "pub fn branch(x: u32) -> u32 { if x > 100 { x * 3 } else { x + 1 } }\n"
        "fn main() { println!(\"{}\", branch(std::env::args().len() as u32)); }\n")
    profdata = str(Path(clang).with_name("llvm-profdata"))
    profiles = []
    for name, arguments in [("low", []), ("high", ["x"] * 150)]:
        raw_dir = work / name
        raw_dir.mkdir()
        subprocess.run([rustc, "source.rs", "--crate-name=example",
                        "-Cprofile-generate=" + str(raw_dir), "-o", "program"],
                       cwd=work, env=env, check=True, capture_output=True)
        subprocess.run([str(work / "program"), *arguments], cwd=work,
                       env=env, check=True, capture_output=True, timeout=120)
        raw_files = list(raw_dir.glob("*.profraw"))
        assert raw_files, "rustc produced no raw profile"
        merged = work / (name + ".profdata")
        subprocess.run([profdata, "merge", "-o", str(merged),
                        *map(str, raw_files)], cwd=work, env=env,
                       check=True, capture_output=True)
        profiles.append(merged.read_bytes())
    assert profiles[0] != profiles[1], "Rust profile runs produced identical data"

    output = work / "target/libexample.rlib"
    depfile = work / "target/example.d"
    profile_file = work / "profile.profdata"
    args = [rustc, "source.rs", "--crate-name=example", "--crate-type=rlib",
            "--emit=link,dep-info", "--out-dir=target", "-Cprofile-use=profile.profdata"]

    def compile_library(wrapper):
        output.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return (completed.stdout, completed.stderr, output.read_bytes(),
                depfile.read_bytes())

    results = []
    for revision, profile in enumerate(profiles):
        profile_file.write_bytes(profile)
        direct = compile_library([])
        before_cold_hits = hits()
        assert compile_library([sccache]) == direct
        assert hits() == before_cold_hits, "sccache ignored the changed Rust profile"
        before_hits = hits()
        assert compile_library([sccache]) == direct
        assert hits() > before_hits, "sccache did not hit the Rust profile action"

        assert compile_library([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", cold
        if revision:
            assert any("profile.profdata" in item for item in cold["changes"]), cold
        assert compile_library([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", warm
        results.append({"fixture": "rust-profile-use", "revision": revision,
                        "oracle_hit": True, "accache": "hit",
                        "artifacts": ["target/example.d", "target/libexample.rlib"]})

    print("PASS oracle Rust profile input invalidation", flush=True)
    return results


def check_unpacked_split_debug(root, env, accache, sccache, rustc, hits, crate_type):
    """Restore every rustc .dwo file omitted by pinned sccache warm hits."""
    fixture = f"rust-{crate_type}-unpacked-split-debug"
    work = root / fixture
    work.mkdir()
    target = work / "target"
    target.mkdir()
    modules = "\n".join(
        f"mod m{index} {{ #[inline(never)] pub fn value() -> u32 {{ {index} }} }}"
        for index in range(16))
    terms = " + ".join(f"m{index}::value()" for index in range(16))
    (work / "library.rs").write_text(
        modules + '\npub fn answer() -> (&\'static str, u32) { '
        f'(include_str!("value.txt"), {terms})' + ' }\n')
    value = work / "value.txt"
    args = [rustc, "--crate-name=example", f"--crate-type={crate_type}",
            "--emit=link,dep-info", "--out-dir=target", "library.rs",
            "-Cdebuginfo=2", "-Csplit-debuginfo=unpacked",
            "-Cextra-filename=-oracle", "-Ccodegen-units=4"]

    def compile_library(wrapper):
        for path in target.iterdir():
            path.unlink()
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        files = {path.name: path.read_bytes() for path in target.iterdir()}
        return completed.stdout, completed.stderr, files

    results = []
    for revision, content in enumerate(["first", "second"]):
        value.write_text(content)
        direct = compile_library([])
        dwo = {name for name in direct[2] if name.endswith(".dwo")}
        assert dwo, "unpacked split debug produced no .dwo files"
        if crate_type == "rlib":
            assert len(dwo) > 1, "rlib codegen units produced fewer than two .dwo files"
        assert compile_library([sccache]) == direct
        before_hits = hits()
        oracle_warm = compile_library([sccache])
        assert hits() > before_hits, "sccache did not hit the unpacked action"
        assert set(direct[2]) - set(oracle_warm[2]) == dwo, oracle_warm[2]
        assert all(oracle_warm[2][name] == direct[2][name]
                   for name in oracle_warm[2]), "sccache changed non-DWO outputs"

        assert compile_library([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", cold
        assert all(any(Path(path).name == name for path in cold["artifacts"])
                   for name in dwo), cold
        if revision:
            assert any("value.txt" in item for item in cold["changes"]), cold
        assert compile_library([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", warm
        assert all(any(Path(path).name == name for path in warm["artifacts"])
                   for name in dwo), warm
        results.append({"fixture": fixture, "revision": revision,
                        "oracle_hit": True, "accache": "hit",
                        "oracle_missing_artifacts": sorted("target/" + name for name in dwo),
                        "artifacts": sorted("target/" + name for name in direct[2])})

    print("PASS oracle Rust", crate_type, "unpacked split debug restoration", flush=True)
    return results


def run_suite(root, accache, sccache, gcc, clang, rustc):
    root = Path(root)
    # Keep socket names short even under long Nix build-directory names.
    env = os.environ | {
        "SCCACHE_DIR": str(root / "sccache"),
        "SCCACHE_SERVER_UDS": str(root / "server.sock"),
        "SCCACHE_IDLE_TIMEOUT": "0",
        "SCCACHE_ERROR_LOG": str(root / "server.log"),
        "LC_ALL": "C",
        "ACCACHE_DIR": str(root / "accache"),
        "ACCACHE_STATE_DIR": str(root / "state"),
    }
    manifest = json.loads(Path(env["ACCACHE_MANIFEST"]).read_text())
    manifest["read_roots"] = ["."]
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    env["ACCACHE_MANIFEST"] = str(manifest_path)
    for key in manifest.get("remove_environment", []):
        env.pop(key, None)
    env.pop("RUSTC_WRAPPER", None)
    env.pop("ACCACHE_VERBOSE", None)
    env.pop("ACCACHE_DISABLE", None)

    def stats():
        result = subprocess.run([sccache, "--show-stats", "--stats-format", "json"],
                                env=env, check=True, capture_output=True)
        return json.loads(result.stdout)["stats"]

    def hits():
        return sum(stats()["cache_hits"]["counts"].values())

    results = []
    subprocess.run([sccache, "--start-server"], env=env | {"SCCACHE_LOG": "debug"}, check=True, capture_output=True)
    try:
        for fixture in fixtures(gcc, clang, rustc):
            work = root / fixture.name
            work.mkdir()
            (work / "target").mkdir()
            for name, contents in fixture.sources.items():
                (work / name).parent.mkdir(parents=True, exist_ok=True)
                (work / name).write_text(contents)
            if fixture.precompile:
                subprocess.run([fixture.compiler, *fixture.precompile], cwd=work,
                               env=env, check=True, capture_output=True)
            sources = set(snapshot(work))

            def clean():
                for path in work.rglob("*"):
                    if path.is_file() and str(path.relative_to(work)) not in sources:
                        path.unlink()

            def invoke(wrapper):
                clean()
                before = snapshot(work)
                completed = subprocess.run([*wrapper, fixture.compiler, *fixture.arguments],
                                           cwd=work, env=env, capture_output=True, timeout=120)
                expected_exit = fixture.direct_exit_code if not wrapper and fixture.direct_exit_code is not None else fixture.exit_code
                assert completed.returncode == expected_exit, (
                    fixture.name, wrapper, completed.returncode, completed.stderr.decode(errors="replace"))
                after = snapshot(work)
                assert all(after.get(path) == value for path, value in before.items()), (
                    fixture.name, "compiler changed an input")
                artifacts = {path: value for path, value in after.items() if path not in sources}
                return completed.returncode, completed.stdout, completed.stderr, artifacts

            def compare(expected, actual, label):
                # Pinned sccache omits the implicit depfile from its stored
                # output list. Check that exact known defect, without relaxing
                # accache's comparison or hiding any other artifact difference.
                if (fixture.name in {"gcc-default-depfile", "clang-default-depfile"}
                        and label == "sccache warm vs direct"):
                    expected = (*expected[:3], {key: value for key, value in expected[3].items()
                                               if key != "source.d"})
                    assert "source.d" not in actual[3], "oracle defect changed; remove this exception"
                missing_oracle_side_files = {
                    "gcc-aux-info": "source.aux",
                    "gcc-explicit-tree-dump": "report.txt",
                    "gcc-opt-report": "report.txt",
                    "gcc-sarif-report": "source.c.sarif",
                    "gcc-sarif-nested-output": "objects/source.c.c.sarif",
                    "clang-serialized-diagnostics": "source.dia",
                }
                if (side_file := missing_oracle_side_files.get(fixture.name)) and label == "sccache warm vs direct":
                    # These accepted flags produce files that pinned sccache
                    # omits from its action result. Accache must restore them.
                    assert side_file in expected[3]
                    expected = (*expected[:3], {key: value for key, value in expected[3].items()
                                               if key != side_file})
                    assert side_file not in actual[3], (
                        "oracle defect changed; remove this exception")
                if fixture.name == "gcc-sarif-nested-output" and label.startswith("sccache "):
                    # The pinned oracle's preprocessing probe writes a SARIF
                    # report in the cwd rather than the requested object dir.
                    assert "objects/source.c.c.sarif" not in actual[3]
                    if label == "sccache cold vs direct":
                        assert "source.c.sarif" in actual[3]
                        expected = (*expected[:3], {key: value for key, value in expected[3].items()
                                                   if key != "objects/source.c.c.sarif"})
                    actual = (*actual[:3], {key: value for key, value in actual[3].items()
                                           if key != "source.c.sarif"})
                if fixture.name in {"gcc-tree-dump", "gcc-multiple-dumps",
                                    "gcc-tree-all-dumps", "gcc-statistics-dump"} and label == "sccache warm vs direct":
                    dump_files = {path for path in expected[3]
                                  if path.startswith("source.c.")}
                    expected_count = {"gcc-tree-dump": 1, "gcc-multiple-dumps": 2,
                                      "gcc-statistics-dump": 1}
                    if fixture.name == "gcc-tree-all-dumps":
                        assert len(dump_files) >= 100, ("unexpected GCC dump files", expected[3])
                    else:
                        assert len(dump_files) == expected_count[fixture.name], (
                            "unexpected GCC dump files", expected[3])
                    expected = (*expected[:3], {key: value for key, value in expected[3].items()
                                               if key not in dump_files})
                    assert dump_files.isdisjoint(actual[3]), (
                        "oracle defect changed; remove this exception")
                if (fixture.name in {"rust-staticlib-metadata-only", "rust-staticlib-all-outputs"}
                        and label == "sccache warm vs direct"):
                    # Pinned sccache loses rustc's empty metadata file for a
                    # staticlib-only crate. Keep the direct/accache comparison
                    # strict and fail if the oracle changes its behavior.
                    assert expected[3]["target/libexample.rmeta"] == (b"", False)
                    expected = (*expected[:3], {key: value for key, value in expected[3].items()
                                               if key != "target/libexample.rmeta"})
                    assert "target/libexample.rmeta" not in actual[3], (
                        "oracle defect changed; remove this exception")
                for field, left, right in zip(["exit", "stdout", "stderr", "artifacts"], expected, actual):
                    if field == "artifacts" and fixture.nondeterministic_outputs:
                        # GCC PCH embeds process-specific state even when direct
                        # compilations receive identical argv and inputs.
                        left = {path: (b"", mode) if path in fixture.nondeterministic_outputs
                                else (data, mode) for path, (data, mode) in left.items()}
                        right = {path: (b"", mode) if path in fixture.nondeterministic_outputs
                                 else (data, mode) for path, (data, mode) in right.items()}
                    assert left == right, (fixture.name, label, field,
                                           {path: (hashlib.sha256(data).hexdigest(), executable)
                                            for path, (data, executable) in left.items()} if isinstance(left, dict) else left,
                                           {path: (hashlib.sha256(data).hexdigest(), executable)
                                            for path, (data, executable) in right.items()} if isinstance(right, dict) else right)

            for revision in range(2 if fixture.changes else 1):
                if revision:
                    for name, contents in fixture.changes.items():
                        (work / name).write_text(contents)
                direct = invoke([])
                if fixture.name == "gcc-opt-report":
                    assert direct[3]["report.txt"][0], "GCC optimization report is empty"
                oracle_cold = invoke([sccache])
                if fixture.direct_exit_code is None:
                    compare(direct, oracle_cold, "sccache cold vs direct")
                    baseline = direct
                else:
                    # The pinned frontend expands a nested @file that rustc
                    # itself leaves literal. Its successful result is the
                    # reference for this sccache-specific extension.
                    assert not direct[3], (fixture.name, "direct rustc wrote outputs")
                    baseline = oracle_cold
                before_hits = hits()
                oracle_warm = invoke([sccache])
                compare(baseline, oracle_warm, "sccache warm vs direct" if baseline is direct else "sccache warm vs cold")
                if fixture.cacheable:
                    for path in fixture.nondeterministic_outputs:
                        if path in oracle_warm[3]:
                            assert oracle_warm[3][path] == oracle_cold[3][path], (
                                fixture.name, "sccache did not replay the cold artifact")
                oracle_hit = hits() > before_hits
                if fixture.name in {"gcc-tree-dump", "gcc-multiple-dumps",
                                    "gcc-tree-all-dumps", "gcc-statistics-dump",
                                    "gcc-explicit-tree-dump",
                                    "gcc-opt-report", "gcc-sarif-report",
                                    "gcc-sarif-nested-output"}:
                    assert oracle_hit, (fixture.name, "sccache report omission was not a hit")

                accache_cold = invoke([accache])
                compare(baseline, accache_cold, "accache cold vs baseline")
                cold_event = json.loads(subprocess.check_output([accache, "explain"], env=env))
                if fixture.name == "rust-nested-response" and revision:
                    assert any("inner.rsp" in change for change in cold_event["changes"]), (
                        fixture.name, "inner response edit was not tracked", cold_event)
                accache_warm = invoke([accache])
                compare(baseline, accache_warm, "accache warm vs baseline")
                if fixture.cacheable:
                    for path in fixture.nondeterministic_outputs:
                        assert accache_warm[3][path] == accache_cold[3][path], (
                            fixture.name, "accache did not replay the cold PCH")
                warm_event = json.loads(subprocess.check_output([accache, "explain"], env=env))
                if fixture.cacheable:
                    assert cold_event["outcome"] == "miss", (fixture.name, cold_event)
                    assert warm_event["outcome"] == "hit", (fixture.name, warm_event)
                    # An oracle that never caches is not a useful hit comparator.
                    assert oracle_hit, (fixture.name, "sccache did not hit", stats())
                else:
                    assert warm_event["outcome"] != "hit", (fixture.name, warm_event)
                results.append({"fixture": fixture.name, "revision": revision,
                                "oracle_hit": oracle_hit, "accache": warm_event["outcome"],
                                "oracle_missing_artifacts": sorted(set(baseline[3]) - set(oracle_warm[3])),
                                "artifacts": sorted(baseline[3])})
            print("PASS oracle", fixture.name, flush=True)

        results.append(check_saved_temporaries(root, env, accache, sccache, rustc, hits))
        results.append(check_assembler_include_invalidation(root, env, accache,
                                                            sccache, gcc, hits))
        results.extend(check_field_named_include(root, env, accache, sccache,
                                                 gcc, clang, hits))
        results.append(check_absolute_inline_assembler_input(root, env, accache,
                                                              sccache, gcc, hits))
        results.extend(check_inline_assembler_inputs(root, env, accache,
                                                     sccache, gcc, clang, hits))
        results.extend(check_clang_profile_use(root, env, accache, sccache,
                                               clang, hits))
        results.extend(check_rust_profile_use(root, env, accache, sccache,
                                              rustc, clang, hits))
        for crate_type in ["rlib", "staticlib"]:
            results.extend(check_unpacked_split_debug(root, env, accache, sccache,
                                                      rustc, hits, crate_type))

        report = json.dumps({"fixtures": results, "sccache_stats": stats()}, sort_keys=True)
        if destination := os.environ.get("ACCACHE_ORACLE_REPORT"):
            Path(destination).write_text(report + "\n")
        print(report)
    finally:
        subprocess.run([sccache, "--stop-server"], env=env, capture_output=True, timeout=30)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="ao-") as directory:
        run_suite(directory, *sys.argv[1:])
