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
        yield Fixture(name + "-failed", compiler, base,
                      {"source.c": "#error intentional oracle failure\n"}, cacheable=False, exit_code=1)
        yield Fixture(name + "-preprocess-only", compiler, ["-E", "source.c"], c_sources, cacheable=False)
        yield Fixture(name + "-unknown-invalid", compiler, base + ["-faccache-intentionally-invalid"],
                      c_sources, cacheable=False, exit_code=1)

    # PCH/PCM serialize diagnostic configuration. Use sccache's forced color
    # setting explicitly so the reference compiler serializes the same options.
    yield Fixture("clang-pch", clang, ["-x", "c-header", "-c", "header.h", "-o", "header.pch", "-fdiagnostics-color=always"],
                  {"header.h": "#define VALUE 42\n"})
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
    yield Fixture("rust-failed", rustc,
                  ["--crate-type=rlib", "--emit=link,dep-info", "--out-dir=target", "library.rs"],
                  {"library.rs": 'compile_error!("intentional oracle failure");\n'}, cacheable=False, exit_code=1)
    yield Fixture("rust-query", rustc, ["--version", "--verbose"], {}, cacheable=False)


def snapshot(work):
    """Observe file contents and executable bits without relying on a parser."""
    return {str(path.relative_to(work)): (path.read_bytes(), bool(path.stat().st_mode & 0o111))
            for path in work.rglob("*") if path.is_file()}


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
                (work / name).write_text(contents)
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
                assert completed.returncode == fixture.exit_code, (
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
                oracle_cold = invoke([sccache])
                compare(direct, oracle_cold, "sccache cold vs direct")
                before_hits = hits()
                oracle_warm = invoke([sccache])
                compare(direct, oracle_warm, "sccache warm vs direct")
                oracle_hit = hits() > before_hits

                accache_cold = invoke([accache])
                compare(direct, accache_cold, "accache cold vs direct")
                cold_event = json.loads(subprocess.check_output([accache, "explain"], env=env))
                accache_warm = invoke([accache])
                compare(direct, accache_warm, "accache warm vs direct")
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
                                "oracle_missing_artifacts": sorted(set(direct[3]) - set(oracle_warm[3])),
                                "artifacts": sorted(direct[3])})
            print("PASS oracle", fixture.name, flush=True)
        report = json.dumps({"fixtures": results, "sccache_stats": stats()}, sort_keys=True)
        if destination := os.environ.get("ACCACHE_ORACLE_REPORT"):
            Path(destination).write_text(report + "\n")
        print(report)
    finally:
        subprocess.run([sccache, "--stop-server"], env=env, capture_output=True, timeout=30)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="ao-") as directory:
        run_suite(directory, *sys.argv[1:])
