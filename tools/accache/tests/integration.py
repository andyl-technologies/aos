"""Exercise real compiler results, invalidation, corruption, and concurrency.

Run with AOS-built accache, GCC, Clang, and rustc paths as the four arguments.
The Nix check supplies the authoritative manifest through ACCACHE_MANIFEST.
"""

import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


binary, gcc, clang, rustc = sys.argv[1:]


def run_suite(root):
    root = Path(root)
    work = root / "work"
    work.mkdir()
    env = {key: value for key, value in os.environ.items() if not key.startswith("ACCACHE_")}
    env.update(ACCACHE_DIR=str(root / "cache"), ACCACHE_STATE_DIR=str(root / "state"))
    env["ACCACHE_MANIFEST"] = os.environ["ACCACHE_MANIFEST"]
    env["LC_ALL"] = "C"
    env["VALUE"] = "first"

    def invoke(compiler, args, expected="miss", extra=None):
        result = subprocess.run([binary, compiler, *args], cwd=work, env=env | (extra or {}), capture_output=True)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        event = json.loads(subprocess.check_output([binary, "explain"], env=env))
        assert event["outcome"] == expected, event
        return event

    for compiler in [gcc, clang]:
        (work / "first").mkdir(exist_ok=True)
        (work / "second").mkdir(exist_ok=True)
        (work / "second/value.h").write_text("#define VALUE 1\n")
        (work / "source.c").write_text('#include <value.h>\nint value(void) { return VALUE; }\n')
        args = ["-c", "source.c", "-o", "source.o", "-I", "first", "-I", "second", "-MD", "-MF", "source.d"]
        first = invoke(compiler, args)
        original = (work / "source.o").read_bytes()
        (work / "source.o").unlink()
        (work / "source.d").unlink()
        invoke(compiler, args, "hit")
        assert (work / "source.o").read_bytes() == original
        assert "value.h" in (work / "source.d").read_text()

        # A newly created earlier include must invalidate without changing any
        # previously recorded input. This catches stale dependency manifests.
        (work / "first/value.h").write_text("#define VALUE 2\n")
        changed = invoke(compiler, args)
        assert changed["action"] != first["action"]
        assert any("first/value.h" in change for change in changed["changes"]), changed
        assert (work / "source.o").read_bytes() != original
        invoke(compiler, args, "hit")
        (work / "first/value.h").unlink()
        invoke(compiler, args, "hit")

        # Negative include results must be rediscovered too.
        (work / "source.c").write_text('#if __has_include("optional.h")\n#include "optional.h"\n#else\n#define X 3\n#endif\nint value(void) { return X; }\n')
        invoke(compiler, args)
        (work / "optional.h").write_text("#define X 4\n")
        invoke(compiler, args)
        (work / "optional.h").unlink()
        invoke(compiler, args, "hit")
        invoke(compiler, args + ["-O2"])
        invoke(compiler, args + ["-O2"], "hit")

        # Compiler failures never become successful action entries.
        (work / "source.c").write_text("this is not valid C;\n")
        failure = subprocess.run([binary, compiler, *args], cwd=work, env=env, capture_output=True)
        assert failure.returncode != 0
        (work / "source.c").write_text("int value(void) { return 7; }\n")
        invoke(compiler, args)

        # A dangling action result is a miss and gets repaired by compilation.
        for path in (root / "cache/cas").glob("*/*"):
            path.unlink()
        invoke(compiler, args)
        invoke(compiler, args, "hit")

    # GCC 16 can add diagnostic file sinks that the pinned sccache argument
    # table does not describe. Restore their reports on a cache hit.
    (work / "source.c").write_text("int diagnostic(void) { return 42; }\n")
    (work / "reports").mkdir()
    sarif = work / "reports/source.c.c.sarif"
    sarif_args = ["-c", str(work / "source.c"), "-o", "reports/source.c.o",
                  "-fdiagnostics-format=sarif-file"]
    invoke(gcc, sarif_args)
    report_bytes = sarif.read_bytes()
    sarif.unlink()
    (work / "reports/source.c.o").unlink()
    invoke(gcc, sarif_args, "hit")
    assert sarif.read_bytes() == report_bytes

    mixed_args = ["-c", "source.c", "-o", "reports/mixed.o",
                  "-fdump-tree-original", "-fdiagnostics-format=sarif-file"]
    invoke(gcc, mixed_args)
    mixed_report = work / "reports/mixed.c.sarif"
    mixed_bytes = mixed_report.read_bytes()
    dump_files = list((work / "reports").glob("mixed.c.*.original"))
    assert len(dump_files) == 1, dump_files
    dump_bytes = dump_files[0].read_bytes()
    (work / "reports/mixed.o").unlink()
    mixed_report.unlink()
    dump_files[0].unlink()
    invoke(gcc, mixed_args, "hit")
    assert mixed_report.read_bytes() == mixed_bytes
    assert dump_files[0].read_bytes() == dump_bytes

    custom_dump_args = ["-c", "source.c", "-o", "custom-dump.o",
                        "-fdump-tree-original", "-dumpbase", "custom"]
    invoke(gcc, custom_dump_args, "bypass")
    custom_dumps = list(work.glob("custom.*.original"))
    assert len(custom_dumps) == 1, custom_dumps
    custom_dumps[0].unlink()
    invoke(gcc, custom_dump_args, "bypass")
    assert custom_dumps[0].is_file(), custom_dumps

    for option in ["add", "set"]:
        report = work / f"{option}.sarif"
        diagnostic_args = ["-c", "source.c", "-o", f"{option}.o",
                           f"-fdiagnostics-{option}-output=sarif:file={report}"]
        invoke(gcc, diagnostic_args)
        report_bytes = report.read_bytes()
        report.unlink()
        (work / f"{option}.o").unlink()
        invoke(gcc, diagnostic_args, "hit")
        assert report.read_bytes() == report_bytes

    html_report = work / "reports/diagnostic.html"
    html_args = ["-c", "source.c", "-o", "reports/diagnostic.o",
                 f"-fdiagnostics-add-output=experimental-html:file={html_report}"]
    invoke(gcc, html_args)
    html_bytes = html_report.read_bytes()
    html_report.unlink()
    (work / "reports/diagnostic.o").unlink()
    invoke(gcc, html_args, "hit")
    assert html_report.read_bytes() == html_bytes

    diagram_report = work / "reports/diagrams.html"
    diagram_args = ["-c", "source.c", "-o", "reports/diagrams.o",
                    "-fdiagnostics-add-output=experimental-html:"
                    f"show-state-diagrams=yes,file={diagram_report}"]
    invoke(gcc, diagram_args)
    diagram_bytes = diagram_report.read_bytes()
    diagram_report.unlink()
    (work / "reports/diagrams.o").unlink()
    invoke(gcc, diagram_args, "hit")
    assert diagram_report.read_bytes() == diagram_bytes

    (work / "library.rs").write_text('pub const VALUE: &str = env!("VALUE");\npub const TEXT: &str = include_str!("message.txt");\n')
    (work / "message.txt").write_text("one")
    (work / "target").mkdir()
    rust_args = ["--crate-name", "example", "--crate-type", "rlib", "--edition=2024", "--emit=link,metadata,dep-info", "--out-dir", str(work / "target"), "library.rs"]
    invoke(rustc, rust_args)
    library = (work / "target/libexample.rlib").read_bytes()
    for path in (work / "target").iterdir():
        path.unlink()
    invoke(rustc, rust_args, "hit")
    assert (work / "target/libexample.rlib").read_bytes() == library
    (work / "message.txt").write_text("two")
    changed = invoke(rustc, rust_args)
    assert any("message.txt" in item for item in changed["changes"])
    invoke(rustc, rust_args, "hit")
    changed = invoke(rustc, rust_args, extra={"VALUE": "second"})
    assert "environment: VALUE" in changed["changes"]
    invoke(rustc, rust_args, "hit", {"VALUE": "second"})

    # Metadata-only actions are useful for Cargo check.
    metadata = [arg.replace("--emit=link,metadata,dep-info", "--emit=metadata,dep-info") for arg in rust_args]
    invoke(rustc, metadata)
    invoke(rustc, metadata, "hit")
    invoke(rustc, rust_args + ["-C", "incremental=target/incremental"], "bypass")
    assert (work / "target/incremental").is_dir()

    # Exercise --extern and transitive search-directory invalidation.
    (work / "consumer.rs").write_text('pub use example::TEXT;\n')
    consumer = ["--crate-name", "consumer", "--crate-type", "rlib", "--edition=2024", "--emit=link,dep-info", "--out-dir", "target", "--extern", "example=target/libexample.rlib", "-L", "dependency=target", "consumer.rs"]
    invoke(rustc, consumer)
    invoke(rustc, consumer, "hit")
    (work / "library.rs").write_text('pub const TEXT: &str = "new";\n')
    invoke(rustc, rust_args)
    invoke(rustc, consumer)
    invoke(rustc, consumer, "hit")

    # Separate derivations differ in their bookkeeping and install rpath even
    # for identical compiler inputs. The manifest removes those variables from
    # execution as well as hashing; otherwise every Nix rebuild would miss.
    (work / "source.c").write_text("int across_derivations(void) { return 91; }\n")
    derivation_args = ["-c", "source.c", "-o", "derivation.o"]
    for index, expected in [(1, "miss"), (2, "hit")]:
        output = f"/nix/store/example-{index}"
        invoke(gcc, derivation_args, expected, {
            "out": output, "name": f"package-{index}", "src": f"/nix/store/source-{index}",
            "NIX_LDFLAGS": f"-Wl,-rpath,{output}/lib",
            "CMAKE_C_COMPILER_LAUNCHER": f"/nix/store/launcher-{index}/bin/accache",
            "CMAKE_CXX_COMPILER_LAUNCHER": f"/nix/store/launcher-{index}/bin/accache",
            "NIX_BUILD_CORES": str(index),
        })

    # Compiler names use the first executable on PATH, then validate that exact
    # executable against the manifest. This is the usual CMake launcher form.
    compiler_path = str(Path(gcc).parent) + os.pathsep + env["PATH"]
    invoke(Path(gcc).name, derivation_args, extra={"PATH": compiler_path})
    invoke(Path(gcc).name, derivation_args, "hit", {"PATH": compiler_path})

    # Independent processes share the same action lock and publish complete
    # results. All use the same working directory, as separate Nix sandboxes do.
    (work / "source.c").write_text("int concurrent(void) { return 77; }\n")
    args = ["-c", "source.c", "-o", "concurrent.o"]
    before = json.loads(subprocess.check_output([binary, "stats"], env=env))
    def concurrent_compile(_):
        return subprocess.run([binary, gcc, *args], cwd=work, env=env, capture_output=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(concurrent_compile, range(12)))
    assert all(result.returncode == 0 for result in results), results
    after = json.loads(subprocess.check_output([binary, "stats"], env=env))
    assert after.get("miss", 0) - before.get("miss", 0) == 1, (before, after)
    assert after.get("hit", 0) - before.get("hit", 0) == 11, (before, after)

    # A changed declared closure forces a new action even with unchanged source.
    policy = json.loads(Path(env["ACCACHE_MANIFEST"]).read_text())
    policy["closure"][0]["narHash"] += "-changed-for-test"
    new_policy = root / "changed-manifest.json"
    new_policy.write_text(json.dumps(policy))
    changed = invoke(gcc, args, extra={"ACCACHE_MANIFEST": str(new_policy)})
    assert "Nix manifest/toolchain closure" in changed["changes"]
    provenance = subprocess.check_output([binary, "provenance", changed["action"]], env=env)
    assert json.loads(provenance)["action"] == changed["action"]
    print("GCC, Clang, Rust, invalidation, restoration, concurrency, and provenance passed")


with tempfile.TemporaryDirectory(prefix="accache-integration-") as directory:
    run_suite(directory)
