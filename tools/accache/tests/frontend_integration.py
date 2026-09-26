"""Real-compiler checks for the pinned sccache frontend's artifact families."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

binary, gcc, clang, rustc = sys.argv[1:]


def suite(root):
    root = Path(root)
    work = root / "work"
    work.mkdir()
    manifest = json.loads(Path(os.environ["ACCACHE_MANIFEST"]).read_text())
    manifest["read_roots"] = [str(work)]
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    env = os.environ | {"ACCACHE_DIR": str(root / "cache"), "ACCACHE_STATE_DIR": str(root / "state"), "ACCACHE_MANIFEST": str(manifest_path), "LC_ALL": "C"}

    def event():
        return json.loads(subprocess.check_output([binary, "explain"], env=env))

    def invoke(compiler, args, expect=None):
        result = subprocess.run([binary, compiler, *args], cwd=work, env=env, capture_output=True)
        assert result.returncode == 0, (args, result.stderr.decode(errors="replace"))
        record = event()
        if expect:
            assert record["outcome"] == expect, (args, record)
        return result, record

    def roundtrip(label, compiler, args):
        _, first = invoke(compiler, args, "miss")
        files = {name: (work / name).read_bytes() for name in first["identity"]["outputs"] if (work / name).is_file()}
        assert files, (label, first)
        for name in files:
            (work / name).unlink()
        invoke(compiler, args, "hit")
        assert all((work / name).read_bytes() == value for name, value in files.items()), label
        print("PASS", label, flush=True)
        return first

    (work / "source.c").write_text("int function(int x) { return x * 7; }\n")
    (work / "source.cc").write_text("template<int N> struct V { static constexpr int value = N; }; int function() { return V<7>::value; }\n")
    for label, compiler in [("gcc", gcc), ("clang", clang)]:
        roundtrip(label + " default output", compiler, ["-c", "source.c"])
        roundtrip(label + " C++ and unknown flags", compiler, ["-c", "source.cc", "-std=c++20", "-O2", "-march=x86-64", "-mtune=generic", "-fno-math-errno", "-Wno-unused-parameter", "-o", label + "-cxx.o"])
        roundtrip(label + " joined options", compiler, ["-c", "source.c", "-DVALUE=9", "-o" + label + "-joined.o"])
        roundtrip(label + " split DWARF", compiler, ["-c", "source.c", "-g", "-gsplit-dwarf", "-o", label + "-debug.o"])
        roundtrip(label + " optional absent DWARF", compiler, ["-c", "source.c", "-gsplit-dwarf", "-o", label + "-no-debug.o"])
        roundtrip(label + " coverage", compiler, ["-c", "source.c", "--coverage", "-o", label + "-coverage.o"])
        roundtrip(label + " profile generation", compiler, ["-c", "source.c", "-fprofile-generate", "-o", label + "-profile.o"])
        roundtrip(label + " default depfile", compiler, ["-c", "source.c", "-MMD", "-MP", "-o", label + "-deps.o"])
        (work / "nested.rsp").write_text('-D"RESPONSE=7" -O2\n')
        (work / "arguments.rsp").write_text('-c source.c @nested.rsp -o "' + label + ' response.o"\n')
        roundtrip(label + " nested response quoting", compiler, ["@arguments.rsp"])
        (work / "nested.rsp").write_text("-DRESPONSE=8 -O2\n")
        _, changed = invoke(compiler, ["@arguments.rsp"], "miss")
        assert any("nested.rsp" in item for item in changed["changes"])
        (work / "header.h").write_text("#define PCH_VALUE 17\n")
        pch = "header.h.gch" if label == "gcc" else "header.pch"
        roundtrip(label + " PCH generation", compiler, ["-x", "c-header", "-c", "header.h", "-o", pch])
        (work / "pch.c").write_text('#include "header.h"\nint pch_value(void) { return PCH_VALUE; }\n')
        pch_args = ["-include-pch", pch] if label == "clang" else []
        roundtrip(label + " PCH consumption", compiler, ["-c", "pch.c", "-o", label + "-pch.o", *pch_args])
        # Remove GCC's implicit PCH before switching to a different compiler.
        (work / pch).unlink()
        (work / "raw.s").write_text('.text\n.globl assembly_function\nassembly_function:\n.byte 0xc3\n')
        roundtrip(label + " raw assembly", compiler, ["-c", "raw.s", "-o", label + "-assembly.o"])
        (work / "source.i").write_text("int preprocessed(void) { return 13; }\n")
        roundtrip(label + " preprocessed input", compiler, ["-c", "source.i", "-o", label + "-preprocessed.o"])
        (work / "assembler-include.S").write_text(
            '.text\n.globl assembly_include\nassembly_include:\n.include "fragment.inc"\n')
        (work / "fragment.inc").write_text(".byte 0xc3\n")
        assembly_args = ["-c", "assembler-include.S", "-I.",
                         "-o", label + "-assembly-include.o"]
        roundtrip(label + " preprocessed assembler include", compiler, assembly_args)
        (work / "fragment.inc").write_text(".byte 0x90\n")
        _, changed = invoke(compiler, assembly_args, "miss")
        assert any("fragment.inc" in item for item in changed["changes"]), changed
        print("PASS", label, "assembler include invalidation", flush=True)

    roundtrip("clang diagnostics", clang, ["-c", "source.c", "--serialize-diagnostics", "diagnostics.dia", "-o", "diagnostic.o"])
    (work / "module.cppm").write_text("export module example; export int answer() { return 42; }\n")
    roundtrip("clang module precompile", clang, ["-std=c++20", "-c", "--precompile", "module.cppm", "-o", "example.pcm"])
    (work / "consumer.cc").write_text("import example; int use() { return answer(); }\n")
    roundtrip("clang module consumption", clang, ["-std=c++20", "-c", "consumer.cc", "-fmodule-file=example=example.pcm", "-o", "module-user.o"])
    roundtrip("clang combined module outputs", clang, ["-std=c++20", "-c", "module.cppm", "-fmodule-output=combined.pcm", "-o", "combined.o"])

    (work / "library.rs").write_text("pub fn answer() -> u32 { 42 }\n")
    (work / "target").mkdir()
    rust_args = ["--crate-name=example", "--crate-type=rlib", "--emit=link,metadata,dep-info", "--out-dir=target", "library.rs", "-Copt-level=2", "--codegen=target-cpu=x86-64", "-Ctarget-feature=+sse2", "--diagnostic-width=100", "--allow=dead_code", "--color=always"]
    roundtrip("rust joined and long options", rustc, rust_args)
    (work / "rust.rsp").write_text("\n".join(rust_args))
    roundtrip("rust response file", rustc, ["@rust.rsp"])
    persistent = root / "persistent-target"
    persistent.mkdir()
    roundtrip("rust persistent target outside source tree", rustc,
              [arg.replace("--out-dir=target", "--out-dir=" + str(persistent)) for arg in rust_args])
    roundtrip("rust staticlib", rustc, ["--crate-name", "static_example", "--crate-type", "staticlib", "--emit=link,dep-info", "--out-dir", "target", "library.rs"])
    roundtrip("Rust save-temps disabled", rustc,
              ["--crate-name=save_temps_disabled", "--crate-type=rlib",
               "--emit=link,dep-info", "--out-dir=target", "library.rs",
               "-Csave-temps=yes", "--codegen=save-temps=no"])
    saved_args = ["--crate-name=save_temps_enabled", "--crate-type=rlib",
                  "--emit=link,dep-info", "--out-dir=target", "library.rs",
                  "-Csave-temps=no", "-Csave-temps=yes"]
    _, saved_temporaries = invoke(rustc, saved_args, "miss")
    saved_paths = [work / path for path in saved_temporaries["artifacts"]]
    assert any(path.suffix == ".bc" for path in saved_paths), saved_paths
    assert any(path.parent.name.startswith(("rmeta", "rustc")) for path in saved_paths), saved_paths
    saved_bytes = {path: path.read_bytes() for path in saved_paths}
    for path in saved_paths:
        path.unlink()
    _, restored_temporaries = invoke(rustc, saved_args, "hit")
    assert all(path.read_bytes() == content for path, content in saved_bytes.items())
    assert set(restored_temporaries["artifacts"]) == set(saved_temporaries["artifacts"])
    print("PASS Rust save-temps warm restoration", flush=True)

    split_saved_args = ["--crate-name=split_saved", "--crate-type=rlib",
                        "--emit=link,dep-info", "--out-dir=target", "library.rs",
                        "-Csave-temps=yes", "-Csplit-debuginfo=unpacked", "-Cdebuginfo=2"]
    _, split_saved = invoke(rustc, split_saved_args, "miss")
    split_paths = [work / path for path in split_saved["artifacts"]]
    assert any(path.suffix == ".dwo" for path in split_paths), split_paths
    split_bytes = {path: path.read_bytes() for path in split_paths}
    for path in split_paths:
        path.unlink()
    invoke(rustc, split_saved_args, "hit")
    assert all(path.read_bytes() == content for path, content in split_bytes.items())
    print("PASS Rust save-temps and split-debug restoration", flush=True)

    for label, crate_type, emit in [
        ("metadata", "rlib", "metadata,dep-info"),
        ("staticlib", "staticlib", "link,dep-info"),
    ]:
        args = [f"--crate-name=saved_{label}", f"--crate-type={crate_type}",
                f"--emit={emit}", "--out-dir=target", "library.rs",
                "-Csave-temps=yes"]
        _, first = invoke(rustc, args, "miss")
        paths = [work / path for path in first["artifacts"]]
        if crate_type == "staticlib":
            assert any(path.parent.name.startswith(("rmeta", "rustc")) for path in paths), paths
        contents = {path: path.read_bytes() for path in paths}
        for path in paths:
            path.unlink()
        _, restored = invoke(rustc, args, "hit")
        assert set(restored["artifacts"]) == set(first["artifacts"])
        assert all(path.read_bytes() == content for path, content in contents.items())
        print(f"PASS Rust save-temps {label} restoration", flush=True)

    saved_target = work / "target" / "concurrent-saved"
    saved_target.mkdir()
    saved_cases = []
    for name, answer in [("first", 11), ("second", 29)]:
        source = work / f"saved-{name}.rs"
        functions = "\n".join(
            f"#[inline(never)] pub fn value_{index}() -> u32 {{ {answer + index} }}"
            for index in range(200))
        source.write_text(functions + "\n")
        args = [f"--crate-name=saved_{name}", "--crate-type=rlib",
                "--emit=link,dep-info", "--out-dir=target/concurrent-saved",
                source.name, "-Csave-temps=yes", "-Ccodegen-units=4"]
        saved_cases.append((name, args))

    def saved_outputs():
        outputs = []
        for path in saved_target.rglob("*"):
            if not path.is_file():
                continue
            parts = list(path.relative_to(saved_target).parts)
            if len(parts) > 1 and parts[0].startswith(("rmeta", "rustc")):
                parts[0] = "rmeta*" if parts[0].startswith("rmeta") else "rustc*"
            outputs.append(("/".join(parts), path.read_bytes()))
        return sorted(outputs)

    direct_saved_outputs = {}
    for name, args in saved_cases:
        result = subprocess.run([rustc, *args], cwd=work, env=env,
                                capture_output=True, timeout=120)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        direct_saved_outputs[name] = saved_outputs()
        shutil.rmtree(saved_target)
        saved_target.mkdir()

    workers = [subprocess.Popen([binary, rustc, *args], cwd=work,
                                env=env | {"ACCACHE_VERBOSE": "1"},
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
               for _, args in saved_cases]
    for worker in workers:
        _, stderr = worker.communicate(timeout=120)
        assert worker.returncode == 0 and b"accache: miss:" in stderr, stderr

    for name, args in saved_cases:
        shutil.rmtree(saved_target)
        saved_target.mkdir()
        _, restored = invoke(rustc, args, "hit")
        assert saved_outputs() == direct_saved_outputs[name], (name, restored)
    print("PASS concurrent Rust save-temps output attribution", flush=True)

    # Both actions write the same .dwo output scope. A warm hit after they
    # compile concurrently must restore the files from its own source.
    concurrent_target = work / "target" / "concurrent"
    concurrent_target.mkdir()
    concurrent_cases = []
    for name, answer in [("first", 11), ("second", 29)]:
        source = work / f"concurrent-{name}.rs"
        source.write_text(f"pub fn answer() -> u32 {{ {answer} }}\n")
        args = ["--crate-name=concurrent_debug", "--crate-type=rlib",
                "--emit=link,dep-info", "--out-dir=target/concurrent",
                source.name, "-Cdebuginfo=2", "-Csplit-debuginfo=unpacked",
                "-Ccodegen-units=4"]
        concurrent_cases.append((name, args))

    def concurrent_outputs():
        return {path.name: path.read_bytes() for path in concurrent_target.iterdir()
                if path.is_file()}

    def clear_concurrent_outputs():
        for path in concurrent_target.iterdir():
            if path.is_file():
                path.unlink()

    direct_outputs = {}
    for name, args in concurrent_cases:
        result = subprocess.run([rustc, *args], cwd=work, env=env,
                                capture_output=True, timeout=120)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        direct_outputs[name] = concurrent_outputs()
        assert any(path.endswith(".dwo") for path in direct_outputs[name])
        clear_concurrent_outputs()

    workers = [subprocess.Popen([binary, rustc, *args], cwd=work,
                                env=env | {"ACCACHE_VERBOSE": "1"},
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
               for _, args in concurrent_cases]
    for worker in workers:
        _, stderr = worker.communicate(timeout=120)
        assert worker.returncode == 0 and b"accache: miss:" in stderr, stderr

    for name, args in concurrent_cases:
        clear_concurrent_outputs()
        _, restored = invoke(rustc, args, "hit")
        assert concurrent_outputs() == direct_outputs[name], (name, restored)
    print("PASS concurrent Rust split-debug output attribution", flush=True)

    _, incremental = invoke(rustc,
                            ["--crate-name=incremental_example", "--crate-type=rlib",
                             "--emit=link,dep-info", "--out-dir=target", "library.rs",
                             "-Cincremental=incremental-state"], "bypass")
    assert "incremental" in incremental["reason"], incremental
    assert (work / "target/libincremental_example.rlib").is_file()
    print("PASS Rust incremental passthrough", flush=True)
    (work / "native.c").write_text("int native(void) { return 23; }\n")
    subprocess.run([gcc, "-c", "native.c", "-o", "native.o"], cwd=work, env=env, check=True)
    ar = str(Path(gcc).with_name("ar"))
    subprocess.run([ar, "crs", "libnative.a", "native.o"], cwd=work, env=env, check=True)
    (work / "native.rs").write_text('unsafe extern "C" { pub fn native() -> i32; }\n')
    native_args = ["--crate-name", "native_example", "--crate-type", "rlib", "--emit=link,dep-info", "--out-dir", "target", "-Lnative=.", "-lstatic=native", "native.rs"]
    roundtrip("rust native archive", rustc, native_args)

    # The proc macro is compiled ordinarily; its consumers are cacheable under
    # the declared read-root contract, including reads absent from dep-info.
    (work / "macro.rs").write_text('extern crate proc_macro; use proc_macro::TokenStream; #[proc_macro] pub fn number(_: TokenStream) -> TokenStream { std::fs::read_to_string("macro-input.txt").unwrap().parse().unwrap() }\n')
    subprocess.run([rustc, "--crate-name", "numbers", "--crate-type=proc-macro", "macro.rs", "-o", "libnumbers.so"], cwd=work, env=env, check=True)
    (work / "macro-input.txt").write_text("41")
    (work / "macro-user.rs").write_text("extern crate numbers; pub const ANSWER: u32 = numbers::number!();\n")
    macro_args = ["--crate-name", "macro_user", "--crate-type", "rlib", "--emit=link,dep-info", "--out-dir", "target", "--extern", "numbers=libnumbers.so", "macro-user.rs"]
    roundtrip("rust procedural macro consumer", rustc, macro_args)
    (work / "macro-input.txt").write_text("42")
    _, changed = invoke(rustc, macro_args, "miss")
    assert any("macro-input.txt" in item for item in changed["changes"])
    invoke(rustc, macro_args, "hit")
    print("PASS procedural macro file invalidation", flush=True)


with tempfile.TemporaryDirectory(prefix="accache-frontends-") as directory:
    suite(directory)
