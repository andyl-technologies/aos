"""Compare compiler behavior with direct execution and pinned sccache.

Every fixture uses identical compiler paths, arguments, environment, working
and output directories for all three implementations. Output inventories are
observed independently of accache's declarations, so a missing side artifact
cannot make the test pass. Warm runs remove every generated artifact first.
The private sccache server is bounded by this process and stopped in finally.
"""

from dataclasses import dataclass, field
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import struct
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
            ("test-coverage", ["-ftest-coverage"]),
            ("profile-arcs", ["-fprofile-arcs"]),
            ("profile-generation", ["-fprofile-generate"]),
            ("depfile", ["-MD", "-MF", "source.d", "-MT", "custom-target"]),
            ("quoted-dep-target", ["-MD", "-MF", "source.d", "-MQ", "custom target"]),
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

        bypass_modes = [
            ("syntax-only", ["-fsyntax-only"]),
            ("save-temps", ["-save-temps=obj"]),
        ]
        if name == "clang":
            bypass_modes.append(("long-save-temps", ["--save-temps=obj"]))
        for suffix, flags in bypass_modes:
            # These accepted driver modes have no ordinary single-object
            # cache contract. Both wrappers must leave every side file intact.
            yield Fixture(name + "-" + suffix, compiler,
                          base + flags, c_sources, cacheable=False)

        # A dependency request forwarded directly to CPP writes a second
        # output. The cache's own dependency probe must not write that output
        # before the compile, and a warm hit must restore it with the object.
        for suffix, flag in [("wp-md", "-Wp,-MD,forwarded.d"),
                             ("wp-mmd", "-Wp,-MMD,forwarded.d")]:
            yield Fixture(name + "-" + suffix, compiler, base + [flag], c_sources,
                          {"value.h": "#define VALUE 73\n"})
        if name == "gcc":
            yield Fixture("gcc-callgraph-info", compiler,
                          base + ["-fcallgraph-info=su"], c_sources,
                          cacheable=False)
            yield Fixture("gcc-wp-mixed-md", compiler,
                          base + ["-Wp,-DUNUSED=1,-MD,forwarded.d"], c_sources,
                          {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-xpreprocessor-md", compiler,
                          base + ["-Xpreprocessor", "-MD", "-Xpreprocessor", "forwarded.d"],
                          c_sources, {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-xpreprocessor-mmd", compiler,
                          base + ["-Xpreprocessor", "-MMD", "-Xpreprocessor", "forwarded.d"],
                          c_sources, {"value.h": "#define VALUE 73\n"})
            for suffix, flags in [
                ("wa-depfile", ["-Wa,--MD,asm.d"]),
                ("wa-mixed-depfile", ["-Wa,--noexecstack,--MD,asm.d"]),
                ("xassembler-depfile", ["-Xassembler", "--MD", "-Xassembler", "asm.d"]),
                ("wa-listing", ["-Wa,-al=listing.lst"]),
                ("xassembler-listing", ["-Xassembler", "-al=listing.lst"]),
                ("wa-listing-and-depfile", ["-Wa,-al=listing.lst,--MD,asm.d"]),
            ]:
                yield Fixture("gcc-" + suffix, compiler,
                              base + ["-pipe", *flags, "-frandom-seed=" + suffix], c_sources,
                              {"value.h": "#define VALUE 73\n"})
        else:
            yield Fixture("clang-compilation-database", compiler,
                          base + ["-MJ", "compile.json"], c_sources,
                          cacheable=False)
            yield Fixture("clang-wp-mixed-md", compiler,
                          base + ["-Wp,-MD,forwarded.d,-DUNUSED=1",
                                  "-frandom-seed=clang-wp-mixed-md"], c_sources,
                          {"value.h": "#define VALUE 73\n"}, cacheable=False)
            yield Fixture("clang-external-assembler-depfile", compiler,
                          base + ["-pipe", "-fno-integrated-as", "-Wa,--MD,asm.d",
                                  "-frandom-seed=external-assembler-depfile"], c_sources,
                          {"value.h": "#define VALUE 73\n"},
                          nondeterministic_outputs={"asm.d"})
            yield Fixture("clang-external-assembler-listing", compiler,
                          base + ["-pipe", "-fno-integrated-as", "-Wa,-al=listing.lst",
                                  "-frandom-seed=external-assembler-listing"], c_sources,
                          {"value.h": "#define VALUE 73\n"},
                          nondeterministic_outputs={"listing.lst"})
        yield Fixture(name + "-imacros", compiler,
                      base + ["-imacros", "macros.h"],
                      {"source.c": "int answer(void) { return VALUE; }\n",
                       "macros.h": "#define VALUE 42\n"},
                      {"macros.h": "#define VALUE 73\n"})
        yield Fixture(name + "-iquote", compiler,
                      base + ["-iquote", "headers"],
                      {"source.c": c_sources["source.c"],
                       "headers/value.h": c_sources["value.h"]},
                      {"headers/value.h": "#define VALUE 73\n"})

        yield Fixture(name + "-stack-usage", compiler,
                      base + ["-fstack-usage"], c_sources,
                      {"value.h": "#define VALUE 73\n"}, cacheable=False)
        if name == "gcc":
            yield Fixture("gcc-aux-info", compiler,
                          base + ["-aux-info", "source.aux"], c_sources,
                          {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-aux-info-joined", compiler,
                          base + ["-aux-info=source.aux"], c_sources,
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
            analyzer_sources = {
                "source.c": '#include "value.h"\nint answer(int *p) { return *p + VALUE; }\n',
                "value.h": "#define VALUE 42\n",
            }
            for suffix, flag, nondeterministic in [
                ("text", "-fdump-analyzer", {"source.c.analyzer.txt"}),
                ("exploded-graph", "-fdump-analyzer-exploded-graph", {"source.c.eg.dot"}),
                ("exploded-nodes-2", "-fdump-analyzer-exploded-nodes-2", {"source.c.eg.txt"}),
                ("exploded-nodes-3", "-fdump-analyzer-exploded-nodes-3", {"source.c.en-*.txt"}),
                ("state-purge", "-fdump-analyzer-state-purge", set()),
                ("supergraph", "-fdump-analyzer-supergraph", set()),
                ("json", "-fdump-analyzer-json", set()),
            ]:
                yield Fixture("gcc-analyzer-" + suffix, compiler,
                              base + ["-fanalyzer", flag], analyzer_sources,
                              {"value.h": "#define VALUE 73\n"},
                              nondeterministic_outputs=nondeterministic)
            diagnostic_sources = {
                "source.c": ('#include "value.h"\n'
                             'int answer(void) { int *p = 0; return *p + VALUE; }\n'),
                "value.h": "#define VALUE 42\n",
            }
            for suffix, flag in [
                ("exploded-paths", "-fdump-analyzer-exploded-paths"),
                ("feasibility", "-fdump-analyzer-feasibility"),
            ]:
                # These dumps only appear when the analyzer finds a path to a
                # diagnostic. A null dereference supplies a stable path.
                yield Fixture("gcc-analyzer-" + suffix, compiler,
                              base + ["-fanalyzer", flag], diagnostic_sources,
                              {"value.h": "#define VALUE 73\n"})
            infinite_loop_sources = {
                "source.c": ('#include "value.h"\n'
                             'void answer(void) { for (;;) { volatile int x = VALUE; (void)x; } }\n'),
                "value.h": "#define VALUE 42\n",
            }
            yield Fixture("gcc-analyzer-infinite-loop", compiler,
                          base + ["-fanalyzer", "-fdump-analyzer-infinite-loop"],
                          infinite_loop_sources, {"value.h": "#define VALUE 73\n"})
            for suffix in ["debug", "earlydebug"]:
                yield Fixture("gcc-" + suffix + "-dump", compiler,
                              base + ["-g", "-fdump-" + suffix], c_sources,
                              {"value.h": "#define VALUE 73\n"},
                              nondeterministic_outputs={"source.c.*." + suffix})
            for suffix in ["noaddr", "unnumbered", "unnumbered-links",
                           "internal-locations", "passes"]:
                yield Fixture("gcc-dump-" + suffix, compiler,
                              base + ["-g", "-fdump-" + suffix], c_sources,
                              {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-debug-dumps", compiler,
                          base + ["-da"], c_sources,
                          {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-joined-debug-dumps", compiler,
                          base + ["-dumpbase=custom"], c_sources)
            yield Fixture("gcc-debug-assembly", compiler,
                          base + ["-dA"], c_sources)
            for stream in ["stdout", "stderr"]:
                yield Fixture(f"gcc-tree-dump-{stream}", compiler,
                              base + [f"-fdump-tree-original={stream}"], c_sources,
                              {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-explicit-tree-dump", compiler,
                          base + ["-fdump-tree-original=report.txt"], c_sources,
                          {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-go-spec", compiler,
                          base + ["-fdump-go-spec=spec.go"],
                          {"source.c": '#include "value.h"\n'
                                       'struct point { int x; };\n'
                                       'int answer(void) { return VALUE; }\n',
                           "value.h": "#define VALUE 42\n"},
                          {"value.h": "#define VALUE 73\n"})
            yield Fixture("gcc-optimization-record", compiler,
                          base + ["-O2", "-fsave-optimization-record"], c_sources,
                          {"value.h": "#define VALUE 73\n"},
                          nondeterministic_outputs={"source.c.opt-record.json.gz"})
            for suffix, option in [
                ("default", "-fdump-final-insns"),
                ("dot", "-fdump-final-insns=."),
                ("explicit", "-fdump-final-insns=final.gkd"),
            ]:
                yield Fixture("gcc-final-insns-" + suffix, compiler,
                              base + ["-O2", option], c_sources,
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
            yield Fixture("gcc-add-sarif-output", compiler,
                          base + ["-fdiagnostics-add-output=sarif:file=added.sarif"],
                          c_sources, {"value.h": "#define VALUE 73\n"},
                          nondeterministic_outputs={"added.sarif"})
            yield Fixture("gcc-add-default-sarif", compiler,
                          base + ["-fdiagnostics-add-output=sarif"], c_sources,
                          {"value.h": "#define VALUE 73\n"},
                          nondeterministic_outputs={"source.c.sarif"})
            yield Fixture("gcc-set-sarif-output", compiler,
                          base + ["-fdiagnostics-set-output=sarif:file=set.sarif"],
                          c_sources, nondeterministic_outputs={"set.sarif"})
            yield Fixture("gcc-sarif-output-parameters", compiler,
                          base + ["-fdiagnostics-set-output=sarif:version=2.1,file=parameters.sarif"],
                          c_sources, nondeterministic_outputs={"parameters.sarif"})
            yield Fixture("gcc-multiple-sarif-outputs", compiler,
                          base + ["-fdiagnostics-add-output=sarif:file=added.sarif",
                                  "-fdiagnostics-set-output=sarif:file=set.sarif"],
                          c_sources, nondeterministic_outputs={"added.sarif", "set.sarif"})
            yield Fixture("gcc-sarif-then-text", compiler,
                          base + ["-fdiagnostics-format=sarif-file",
                                  "-fdiagnostics-format=text"],
                          c_sources, nondeterministic_outputs={"source.c.sarif"})
            yield Fixture("gcc-html-output", compiler,
                          base + ["-fdiagnostics-add-output=experimental-html"],
                          c_sources, nondeterministic_outputs={"source.c.html"})
            yield Fixture("gcc-html-output-options", compiler,
                          base + ["-fdiagnostics-set-output=experimental-html:css=no,javascript=no,file=report.html"],
                          c_sources, nondeterministic_outputs={"report.html"})
            diagram_sources = {
                "source.c": '#include "value.h"\n'
                            'int answer(void) { int *p = 0; return *p + VALUE; }\n',
                "value.h": "#define VALUE 42\n",
            }
            for suffix, options, report in [
                ("cfgs", "cfgs=yes", "cfgs.html"),
                ("state-diagrams", "show-state-diagrams=yes", "state.html"),
                ("graph-details", "show-state-diagrams=yes,show-graph-dot-src=yes,show-graph-sarif=yes",
                 "details.html"),
            ]:
                yield Fixture("gcc-html-" + suffix, compiler,
                              base + ["-fanalyzer", "-fdiagnostics-add-output=experimental-html:"
                                      + options + ",file=" + report], diagram_sources,
                              {"value.h": "#define VALUE 73\n"},
                              nondeterministic_outputs={report})
            yield Fixture("gcc-text-output-options", compiler,
                          base + ["-Wall", "-fdiagnostics-add-output=text:color=no,show-nesting=no,cfgs=no"],
                          {"source.c": "int answer(void) { int unused = 1; return 42; }\n"})
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
    for name, emits in [
        ("named-link", "link=target/custom.rlib"),
        ("named-dep-info", "link,dep-info=target/custom.d"),
        ("named-link-and-metadata", "link=target/custom.rlib,metadata"),
    ]:
        # The pinned Rust frontend treats per-emission paths as noncacheable.
        # Passthrough still preserves rustc's explicitly named output files.
        yield Fixture("rust-" + name, rustc,
                      ["--crate-name=example", "--crate-type=rlib",
                       "--out-dir=target", "library.rs", "--emit=" + emits],
                      rust_sources, {"value.txt": "second"}, cacheable=False)
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


def check_clang_driver_dependency_file(root, env, accache, sccache, clang):
    """Bypass a driver-ignored cc1 option that makes pinned sccache fail."""
    work = root / "clang-driver-dependency-file"
    work.mkdir()
    (work / "source.c").write_text('#include "value.h"\nint answer(void) { return VALUE; }\n')
    args = [clang, "-c", "source.c", "-o", "source.o", "-MD",
            "-dependency-file", "unused.d", "-frandom-seed=clang-driver-dependency-file"]
    sources = {"source.c", "value.h"}
    results = []

    def compile_object(wrapper):
        for name in ["source.o", "source.d", "unused.d"]:
            (work / name).unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        artifacts = {name: value for name, value in snapshot(work).items()
                     if name not in sources}
        return completed, artifacts

    for revision, value in enumerate([42, 73]):
        (work / "value.h").write_text(f"#define VALUE {value}\n")
        direct, expected = compile_object([])
        assert direct.returncode == 0 and set(expected) == {"source.o", "source.d"}, (
            revision, direct.stderr, expected)

        oracle, _ = compile_object([sccache])
        assert oracle.returncode != 0 and b"failed to zip up compiler outputs" in oracle.stderr, (
            revision, oracle.returncode, oracle.stderr)

        for attempt in range(2):
            actual, artifacts = compile_object([accache])
            assert (actual.returncode, actual.stdout, actual.stderr, artifacts) == (
                direct.returncode, direct.stdout, direct.stderr, expected), (
                    revision, attempt, actual.stderr, artifacts)
            event = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert (event["outcome"] == "bypass"
                    and "Clang driver ignores -dependency-file" in event["reason"]), event

        results.append({"fixture": "clang-driver-dependency-file", "revision": revision,
                        "oracle_hit": False, "accache": "bypass",
                        "oracle_error": "failed to zip up compiler outputs",
                        "artifacts": sorted(expected)})

    print("PASS oracle clang-driver-dependency-file passthrough", flush=True)
    return results


def check_clang_cc1_dependency_file(root, env, accache, sccache, clang, hits):
    """Cache the cc1 depfile that overrides the driver's requested path."""
    results = []
    for fixture, dependency_args in [
        ("clang-cc1-dependency-file", ["-MD", "-MF", "source.d"]),
        ("clang-cc1-dependency-file-md", ["-MD"]),
        ("clang-cc1-dependency-file-mmd", ["-MMD"]),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "source.c").write_text(
            '#include "value.h"\nint answer(void) { return VALUE; }\n')
        args = [clang, "-c", "source.c", "-o", "source.o", *dependency_args,
                "-Xclang", "-dependency-file", "-Xclang", "side.d",
                "-frandom-seed=" + fixture]

        def compile_object(wrapper):
            for name in ["source.o", "source.d", "side.d"]:
                (work / name).unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            artifacts = {name: value for name, value in snapshot(work).items()
                         if name not in {"source.c", "value.h"}}
            return completed, artifacts

        for revision, value in enumerate([42, 73]):
            (work / "value.h").write_text(f"#define VALUE {value}\n")
            direct, expected = compile_object([])
            assert direct.returncode == 0 and set(expected) == {"source.o", "side.d"}, (
                fixture, revision, direct.stderr, expected)

            oracle_errors = 0
            oracle_hits = 0
            oracle_missing = set()
            for _ in range(2):
                before_hits = hits()
                oracle, oracle_artifacts = compile_object([sccache])
                oracle_hits += hits() > before_hits
                if oracle.returncode == 0:
                    assert (oracle.stdout, oracle.stderr,
                            oracle_artifacts.get("source.o")) == (
                                direct.stdout, direct.stderr, expected["source.o"]), (
                                    fixture, revision, oracle.stderr,
                                    sorted(oracle_artifacts), sorted(expected))
                    missing = set(expected) - set(oracle_artifacts)
                    assert not (set(oracle_artifacts) - set(expected))
                    assert missing <= {"side.d"}, (fixture, revision, missing)
                    oracle_missing.update(missing)
                else:
                    assert (oracle.returncode == 254
                            and b"failed to zip up compiler outputs" in oracle.stderr
                            and b"source.d" in oracle.stderr), (
                                fixture, revision, oracle.returncode, oracle.stderr)
                    oracle_errors += 1
            if "-MF" in dependency_args:
                assert oracle_errors, (fixture, revision,
                                       "sccache unexpectedly published the cc1 depfile")
            else:
                assert "side.d" in oracle_missing, (fixture, revision,
                                                    "sccache retained the implicit cc1 depfile")

            for attempt, outcome in enumerate(["miss", "hit"]):
                actual, artifacts = compile_object([accache])
                assert (actual.returncode, actual.stdout, actual.stderr, artifacts) == (
                    direct.returncode, direct.stdout, direct.stderr, expected), (
                        fixture, revision, attempt, actual.stderr, artifacts)
                event = json.loads(subprocess.check_output([accache, "explain"], env=env))
                assert event["outcome"] == outcome, (fixture, revision, attempt, event)
                if revision and attempt == 0:
                    assert any("value.h" in item for item in event["changes"]), event

            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": bool(oracle_hits),
                            "oracle_errors": oracle_errors,
                            "oracle_missing_artifacts": sorted(oracle_missing),
                            "accache": "hit", "artifacts": sorted(expected)})

        print("PASS oracle", fixture, "restoration", flush=True)
    return results


def check_assembler_general_listing_passthrough(root, env, accache, sccache, gcc, hits):
    """Keep assembler reports with embedded timestamps live on every call."""
    results = []
    for name, flags in [
        ("gcc-wa-general-listing", ["-Wa,-ag=listing.lst"]),
        ("gcc-xassembler-general-listing", ["-Xassembler", "-ag=listing.lst"]),
    ]:
        work = root / name
        work.mkdir()
        (work / "source.c").write_text("int answer(void) { return 42; }\n")
        args = [gcc, "-c", "source.c", "-o", "source.o", "-pipe", *flags,
                "-frandom-seed=" + name]

        def compile_object(wrapper):
            (work / "source.o").unlink(missing_ok=True)
            (work / "listing.lst").unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (name, wrapper, completed.stderr)
            object_bytes = (work / "source.o").read_bytes()
            listing = work / "listing.lst"
            return (completed.stdout, completed.stderr, object_bytes,
                    listing.read_bytes() if listing.exists() else None)

        direct = compile_object([])
        assert direct[3] is not None and b"time stamp" in direct[3], name

        oracle_cold = compile_object([sccache])
        assert oracle_cold[2] == direct[2] and oracle_cold[3] is not None, name
        before_hits = hits()
        oracle_warm = compile_object([sccache])
        assert hits() > before_hits and oracle_warm[3] is None, (
            name, "pinned sccache listing omission changed", oracle_warm)

        for attempt in range(2):
            actual = compile_object([accache])
            assert (actual[:3] == direct[:3]
                    and actual[3] is not None and b"time stamp" in actual[3]), (
                name, attempt, actual)
            event = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert (event["outcome"] == "bypass"
                    and "assembler general listing contains a timestamp" in event["reason"]), event

        results.append({"fixture": name, "revision": 0, "oracle_hit": True,
                        "accache": "bypass", "oracle_missing_artifacts": ["listing.lst"],
                        "artifacts": ["listing.lst", "source.o"]})
        print("PASS oracle", name, "passthrough", flush=True)

    return results


def check_rust_diagnostic_passthrough(root, env, accache, sccache, rustc, hits):
    """Keep unstable Rust profiling, traces, dumps, and timings live."""
    results = []
    rust_env = env | {"RUSTC_BOOTSTRAP": "1"}
    cases = [
        ("self-profile", "-Zself-profile=profiles", "profiles/*.mm_profdata"),
        ("time-passes", "-Ztime-passes", None),
        ("llvm-time-trace", "-Zllvm-time-trace", "target/*.llvm_timings.json"),
        ("dump-mir", "-Zdump-mir=SimplifyCfg", "mir_dump/*.mir"),
        ("metrics-dir", "-Zmetrics-dir=metrics", "metrics/*.json"),
        ("nll-facts", "-Znll-facts=yes", "nll-facts/*/*.facts"),
        ("dump-mono-stats", "-Zdump-mono-stats", "*.mono_items.md"),
        ("profile-closures", "-Zprofile-closures", "closure_profile_*.csv"),
        ("print-codegen-stats-json", "-Zprint-codegen-stats-json=stats.json", "stats.json"),
        ("remark-dir", ["-Zremark-dir=remarks", "-Cremark=all",
                        "-Copt-level=3", "-Cdebuginfo=1"], "remarks/*.yaml"),
        ("split-dwarf-out-dir", ["-Zsplit-dwarf-out-dir=split-debug",
                                 "-Csplit-debuginfo=unpacked", "-Cdebuginfo=2"],
         "split-debug/*.dwo"),
        ("temps-dir", ["-Ztemps-dir=temporaries", "-Csave-temps=yes"],
         "temporaries/*.o"),
    ]
    for name, flag, side_pattern in cases:
        work = root / f"rust-{name}"
        work.mkdir()
        (work / "target").mkdir()
        (work / "profiles").mkdir()
        (work / "metrics").mkdir()
        (work / "remarks").mkdir()
        (work / "split-debug").mkdir()
        (work / "temporaries").mkdir()
        (work / "library.rs").write_text(
            "#[inline(always)] pub fn helper(x: u32) -> u32 { x + 1 }\n"
            "pub fn answer() -> u32 { let f = |x| helper(x); f(41) }\n")
        flags = flag if isinstance(flag, list) else [flag]
        args = [rustc, "--crate-name=example", "--crate-type=rlib", "--emit=link,dep-info",
                "--out-dir=target", "library.rs", "-Cmetadata=oracle-" + name, *flags]

        def compile_library(wrapper):
            for path in work.rglob("*"):
                if path.is_file() and path.name != "library.rs":
                    path.unlink()
            completed = subprocess.run([*wrapper, *args], cwd=work, env=rust_env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (name, wrapper, completed.stderr)
            artifacts = {path: contents for path, contents in snapshot(work).items()
                         if path != "library.rs"}
            side_files = {path for path in artifacts
                          if side_pattern and fnmatch.fnmatchcase(path, side_pattern)}
            return completed, artifacts, side_files

        direct = compile_library([])
        assert {"target/libexample.rlib", "target/example.d"}.issubset(direct[1]), name
        if side_pattern:
            assert (direct[2] and (name == "remark-dir"
                    or any(direct[1][path][0] for path in direct[2]))), (name, direct[2])
        else:
            assert b"parse_crate" in direct[0].stderr, name

        oracle_cold = compile_library([sccache])
        assert oracle_cold[1]["target/libexample.rlib"] == direct[1]["target/libexample.rlib"], name
        before_hits = hits()
        oracle_warm = compile_library([sccache])
        assert hits() > before_hits, (name, "pinned sccache did not hit")

        for attempt in range(2):
            actual = compile_library([accache])
            assert (actual[1]["target/libexample.rlib"] == direct[1]["target/libexample.rlib"]
                    and actual[1]["target/example.d"] == direct[1]["target/example.d"]), (
                name, attempt, actual[1])
            if side_pattern:
                assert (actual[2] and (name == "remark-dir"
                        or any(actual[1][path][0] for path in actual[2]))), (
                    name, attempt, actual[2])
            else:
                assert b"parse_crate" in actual[0].stderr, (name, attempt, actual[0].stderr)
            event = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert (event["outcome"] == "bypass"
                    and f"Rust -Z{name} has invocation-specific output" in event["reason"]), event

        results.append({"fixture": f"rust-{name}", "revision": 0, "oracle_hit": True,
                        "accache": "bypass",
                        "oracle_missing_artifacts": sorted(direct[2] - oracle_warm[2]),
                        "artifacts": sorted(direct[1])})
        print("PASS oracle rust", name, "passthrough", flush=True)

    return results


def check_rust_staged_compilation_passthrough(root, env, accache, sccache, rustc):
    """Preserve rustc modes that replace or consume the normal library output."""
    results = []
    rust_env = env | {"RUSTC_BOOTSTRAP": "1"}
    for name in ["no-analysis", "no-link", "link-only", "parse-crate-root-only", "unpretty"]:
        work = root / f"rust-{name}"
        work.mkdir()
        target = work / "target"
        target.mkdir()
        (work / "library.rs").write_text("pub fn answer() -> u32 { 42 }\n")
        if name == "link-only":
            staged_args = [rustc, "--crate-name=example", "--crate-type=rlib",
                           "--emit=link,dep-info", "--out-dir=target", "library.rs",
                           "-Zno-link"]
            staged = subprocess.run(staged_args, cwd=work, env=rust_env,
                                    capture_output=True, timeout=120)
            assert staged.returncode == 0, staged.stderr
            assert (target / "example.rlink").is_file(), name
            source = "target/example.rlink"
        else:
            source = "library.rs"

        args = [rustc, "--crate-name=example", "--crate-type=rlib",
                "--emit=link,dep-info", "--out-dir=target", source,
                "-Zunpretty=hir-tree" if name == "unpretty" else "-Z" + name]

        def compile_case(wrapper):
            if name == "link-only":
                # rustc consumes the staged object while constructing the rlib.
                staged = subprocess.run(staged_args, cwd=work, env=rust_env,
                                        capture_output=True, timeout=120)
                assert staged.returncode == 0, staged.stderr
                (target / "libexample.rlib").unlink(missing_ok=True)
            else:
                for path in target.iterdir():
                    if path.is_file():
                        path.unlink()
            completed = subprocess.run([*wrapper, *args], cwd=work, env=rust_env,
                                       capture_output=True, timeout=120)
            artifacts = {path: contents for path, contents in snapshot(work).items()
                         if path.startswith("target/") and (name != "link-only"
                         or path == "target/libexample.rlib")}
            return completed.returncode, completed.stdout, completed.stderr, artifacts

        direct = compile_case([])
        assert direct[0] == 0, (name, direct[2])
        if name == "no-link":
            assert ("target/example.rlink" in direct[3]
                    and any(path.endswith(".o") for path in direct[3])
                    and "target/libexample.rlib" not in direct[3]), direct[3]
        elif name == "link-only":
            assert "target/libexample.rlib" in direct[3], direct[3]
        elif name == "unpretty":
            assert (set(direct[3]) == {"target/example.d"}
                    and b"Hir" in direct[1]), (direct[1][:100], direct[3])
        elif name == "no-analysis":
            assert set(direct[3]) == {"target/example.d"}, direct[3]
        else:
            assert not direct[3], direct[3]

        oracle_cold = compile_case([sccache])
        oracle_warm = compile_case([sccache])
        oracle_failure = (b"Failed to parse dep info for example" if name in {
            "link-only", "parse-crate-root-only"}
            else b"failed to zip up compiler outputs")
        for oracle in [oracle_cold, oracle_warm]:
            assert (oracle[0] == 254 and oracle_failure in oracle[2]
                    and oracle[3] == direct[3]), (
                name, oracle[0], oracle[2][:300], sorted(oracle[3]))

        for attempt in range(2):
            actual = compile_case([accache])
            assert actual == direct, (name, attempt, actual[:3], direct[:3],
                                      sorted(actual[3]), sorted(direct[3]))
            event = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert (event["outcome"] == "bypass"
                    and f"Rust -Z{name} changes the compilation or output contract"
                    in event["reason"]), event

        results.append({"fixture": "rust-" + name, "revision": 0,
                        "oracle_exit_code": 254,
                        "oracle_failure": oracle_failure.decode(),
                        "accache": "bypass", "artifacts": sorted(direct[3])})
        print("PASS oracle rust", name, "passthrough", flush=True)

    return results


def check_rust_no_codegen(root, env, accache, sccache, rustc, hits):
    """Cache metadata-only rlibs emitted by rustc's no-codegen mode."""
    work = root / "rust-no-codegen"
    work.mkdir()
    (work / "target").mkdir()
    source = work / "library.rs"
    library = work / "target/libexample.rlib"
    depfile = work / "target/example.d"
    rust_env = env | {"RUSTC_BOOTSTRAP": "1"}
    args = [rustc, "--crate-name=example", "--crate-type=rlib",
            "--emit=link,dep-info", "--out-dir=target", "library.rs", "-Zno-codegen"]

    def compile_library(wrapper):
        library.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=rust_env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return (completed.stdout, completed.stderr,
                library.read_bytes(), depfile.read_bytes())

    results = []
    previous_library = None
    for revision, answer in enumerate([42, 73]):
        source.write_text(f"pub fn answer() -> u32 {{ {answer} }}\n")
        direct = compile_library([])
        if previous_library is not None:
            assert direct[2] != previous_library, "source edit left metadata unchanged"
        previous_library = direct[2]

        before_hits = hits()
        assert compile_library([sccache]) == direct
        assert hits() == before_hits, "sccache ignored the changed source"
        before_hits = hits()
        assert compile_library([sccache]) == direct
        assert hits() > before_hits, "sccache did not warm-hit"

        assert compile_library([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
        assert cold["outcome"] == "miss", (revision, cold)
        assert compile_library([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
        assert warm["outcome"] == "hit", (revision, warm)
        results.append({"fixture": "rust-no-codegen", "revision": revision,
                        "oracle_hit": True, "accache": "hit",
                        "artifacts": ["target/libexample.rlib", "target/example.d"]})

    print("PASS oracle rust-no-codegen metadata invalidation", flush=True)
    return results


def check_custom_dump_passthrough(root, env, accache, sccache, gcc, hits):
    """Keep GCC's separate dump naming flags in the pinned frontend's bypass path."""
    results = []
    cases = [
        ("dumpbase", ["-dumpbase", "custom"], "custom.*.original"),
        ("dumpdir", ["-dumpdir", "prefix-"], "prefix-source.c.*.original"),
    ]
    for name, flags, pattern in cases:
        work = root / f"gcc-custom-{name}"
        work.mkdir()
        (work / "source.c").write_text("int answer(void) { return 42; }\n")
        args = [gcc, "-c", "source.c", "-o", "source.o", "-fdump-tree-original", *flags]

        def compile_object(wrapper):
            for path in [work / "source.o", *work.glob(pattern)]:
                path.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (name, wrapper, completed.stderr)
            reports = list(work.glob(pattern))
            assert len(reports) == 1, (name, reports)
            return (work / "source.o").read_bytes(), reports[0].read_bytes()

        direct = compile_object([])
        before_hits = hits()
        assert compile_object([sccache]) == direct
        assert compile_object([sccache]) == direct
        assert hits() == before_hits, (name, "pinned sccache unexpectedly cached")

        for _ in range(2):
            assert compile_object([accache]) == direct
            event = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert event["outcome"] == "bypass", (name, event)

        results.append({"fixture": f"gcc-custom-{name}", "revision": 0,
                        "oracle_hit": False, "accache": "bypass",
                        "artifacts": ["source.o", next(work.glob(pattern)).name]})
        print("PASS oracle GCC custom", name, "passthrough", flush=True)
    return results


def check_ada_specs(root, env, accache, sccache, gcc, hits):
    """Restore header-derived Ada specs omitted by pinned sccache warm hits."""
    results = []
    for name, flags in [
        ("gcc-ada-spec", ["-fdump-ada-spec"]),
        ("gcc-ada-spec-slim", ["-fdump-ada-spec-slim"]),
        ("gcc-ada-spec-parent", ["-fdump-ada-spec", "-fada-spec-parent=Bindings"]),
    ]:
        work = root / name
        work.mkdir()
        (work / "objects").mkdir()
        (work / "source.c").write_text(
            '#include "header.h"\n'
            'int answer(void) { struct point p = {1, 2}; return p.x; }\n')
        args = [gcc, "-c", "source.c", "-o", "objects/source.o", *flags]

        def compile_object(wrapper):
            for path in work.rglob("*"):
                if path.is_file() and path.name not in {"source.c", "header.h"}:
                    path.unlink()
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (name, wrapper, completed.stderr)
            files = snapshot(work)
            files.pop("source.c")
            files.pop("header.h")
            return completed.stdout, completed.stderr, files

        for revision, fields in enumerate(["int x;", "int x; int y;"]):
            (work / "header.h").write_text(f"struct point {{ {fields} }};\n")
            direct = compile_object([])
            ada_files = {path for path in direct[2] if path.endswith(".ads")}
            assert ada_files and "objects/source.o" in direct[2], (name, direct[2])

            oracle_cold = compile_object([sccache])
            assert oracle_cold == direct, (name, revision, "sccache cold", oracle_cold, direct)
            before_hits = hits()
            oracle_warm = compile_object([sccache])
            assert hits() > before_hits, (name, revision, "sccache did not hit")
            assert ada_files.isdisjoint(oracle_warm[2]), (name, revision, oracle_warm[2])

            assert compile_object([accache]) == direct, (name, revision, "accache cold")
            cold_event = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert cold_event["outcome"] == "miss", (name, revision, cold_event)
            assert compile_object([accache]) == direct, (name, revision, "accache warm")
            warm_event = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert warm_event["outcome"] == "hit", (name, revision, warm_event)

            results.append({"fixture": name, "revision": revision,
                            "oracle_hit": True, "accache": "hit",
                            "oracle_missing_artifacts": sorted(ada_files),
                            "artifacts": sorted(direct[2])})

        print("PASS oracle", name, flush=True)
    return results


def check_gcc_joined_depfile(root, env, accache, sccache, gcc, hits):
    """Restore dependency files named by GCC's joined -MF spellings."""
    results = []
    for fixture, flags, output in [
        ("gcc-mf-joined", ["-MD", "-MFdeps.d"], "deps.d"),
        ("gcc-mf-joined-equals", ["-MD", "-MF=deps.d"], "=deps.d"),
        ("gcc-mf-mmd-joined", ["-MMD", "-MFdeps.d"], "deps.d"),
        ("gcc-mf-joined-last",
         ["-MD", "-MF", "first.d", "-MFdeps.d"], "deps.d"),
        ("gcc-mf-separated-last",
         ["-MD", "-MFfirst.d", "-MF", "deps.d"], "deps.d"),
        ("gcc-mf-wp-overrides",
         ["-MD", "-MFdriver.d", "-Wp,-MD,wp.d"], "wp.d"),
        ("gcc-mf-xpreprocessor-overrides",
         ["-MD", "-MFdriver.d", "-Xpreprocessor", "-MD",
          "-Xpreprocessor", "xp.d"], "xp.d"),
        ("gcc-mf-wp-same",
         ["-MD", "-MFwp.d", "-Wp,-MD,wp.d"], "wp.d"),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "source.c").write_text(
            '#include "value.h"\nint answer(void) { return VALUE; }\n')
        header = work / "value.h"
        object_file = work / "source.o"
        depfile = work / output
        args = [gcc, "-c", "source.c", "-o", "source.o", *flags]

        def compile_object(wrapper):
            object_file.unlink(missing_ok=True)
            for path in work.glob("*.d"):
                path.unlink()
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            other_depfiles = sorted(path.name for path in work.glob("*.d")
                                    if path != depfile)
            return (completed.returncode, completed.stdout, completed.stderr,
                    object_file.read_bytes() if object_file.exists() else None,
                    depfile.read_bytes() if depfile.exists() else None,
                    other_depfiles)

        first_object = None
        for revision, value in enumerate([42, 73]):
            header.write_text(f"#define VALUE {value}\n")
            direct = compile_object([])
            assert (direct[0] == 0 and direct[3] and direct[4]
                    and not direct[5]), (fixture, direct)
            if first_object is None:
                first_object = direct[3]
            else:
                assert direct[3] != first_object, (fixture, "header edit had no effect")

            oracle_cold = compile_object([sccache])
            if oracle_cold[0] == 0:
                assert oracle_cold[3] == direct[3], (fixture, revision, oracle_cold)
            before_hits = hits()
            oracle_warm = compile_object([sccache])
            oracle_hit = hits() > before_hits
            if oracle_warm[0] == 0:
                assert oracle_warm[3] == direct[3], (fixture, revision, oracle_warm)

            assert compile_object([accache]) == direct, (fixture, revision, "cold")
            cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            assert compile_object([accache]) == direct, (fixture, revision, "warm")
            warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)

            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": oracle_hit,
                            "oracle_exit_code": oracle_warm[0],
                            "oracle_missing_artifacts": [output] if oracle_warm[4] is None else [],
                            "oracle_extra_depfiles": oracle_warm[5],
                            "accache": "hit", "artifacts": ["source.o", output]})

        print("PASS oracle", fixture, "joined dependency output", flush=True)
    return results


def check_c_timing_passthrough(root, env, accache, sccache, gcc, clang, hits):
    """Keep per-invocation timing streams and append-only timing files live."""
    results = []
    for name, compiler, flag in [("gcc-time-stderr", gcc, "-time"),
                                 ("gcc-time-file", gcc, "-time=timings.txt"),
                                 ("gcc-time-report", gcc, "-ftime-report"),
                                 ("clang-time-report", clang, "-ftime-report"),
                                 ("clang-time-report-per-pass", clang,
                                  "-ftime-report=per-pass"),
                                 ("clang-time-report-per-pass-run", clang,
                                  "-ftime-report=per-pass-run")]:
        work = root / name
        work.mkdir()
        (work / "source.c").write_text("int answer(void) { return 42; }\n")
        args = [compiler, "-c", "source.c", "-o", "source.o", flag]
        timing = work / "timings.txt"

        def compile_object(wrapper):
            (work / "source.o").unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (name, wrapper, completed.stderr)
            return (completed.stdout, completed.stderr,
                    (work / "source.o").read_bytes())

        direct = compile_object([])
        assert direct[2], (name, "direct compiler produced no object")
        if "time-report" in name:
            expected_header = b"Time variable" if name.startswith("gcc-") else b"Total"
            assert expected_header in direct[1], (name, direct[1])
        assert compile_object([sccache])[2] == direct[2]
        before_hits = hits()
        assert compile_object([sccache])[2] == direct[2]
        oracle_hit = hits() > before_hits

        for _ in range(2):
            previous_size = timing.stat().st_size if timing.exists() else 0
            actual = compile_object([accache])
            assert actual[2] == direct[2]
            if "time-report" in name:
                assert expected_header in actual[1], (name, actual[1])
            event = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert event["outcome"] == "bypass" and "timing output" in event["reason"], event
            if timing.exists():
                assert timing.stat().st_size > previous_size, (name, "timing append was skipped")

        assert timing.exists() == (name == "gcc-time-file"), name
        results.append({"fixture": name, "revision": 0, "oracle_hit": oracle_hit,
                        "accache": "bypass", "oracle_missing_artifacts": [],
                        "artifacts": ["source.o"] + (["timings.txt"] if timing.exists() else [])})
        print("PASS oracle", name, flush=True)
    return results


def check_gcc_analyzer_stderr_passthrough(root, env, accache, sccache, gcc, hits):
    """Keep GCC analyzer traces live because they include process addresses."""
    work = root / "gcc-analyzer-stderr"
    work.mkdir()
    (work / "source.c").write_text("int answer(int *p) { return *p; }\n")
    args = [gcc, "-c", "source.c", "-o", "source.o", "-fanalyzer",
            "-fdump-analyzer-stderr"]

    def compile_object(wrapper):
        (work / "source.o").unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr[-400:])
        assert b"entering:" in completed.stderr, (wrapper, completed.stderr[-400:])
        return completed.stderr, (work / "source.o").read_bytes()

    direct = compile_object([])
    oracle_cold = compile_object([sccache])
    before_hits = hits()
    oracle_warm = compile_object([sccache])
    assert hits() > before_hits, "sccache did not cache the analyzer trace"
    assert oracle_cold[1] == oracle_warm[1] == direct[1]

    for _ in range(2):
        actual = compile_object([accache])
        assert actual[1] == direct[1]
        event = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert (event["outcome"] == "bypass"
                and "invocation-specific addresses" in event["reason"]), event

    print("PASS oracle GCC analyzer stderr passthrough", flush=True)
    return {"fixture": "gcc-analyzer-stderr", "revision": 0,
            "oracle_hit": True, "accache": "bypass", "artifacts": ["source.o"]}


def check_saved_temporaries(root, env, accache, sccache, rustc, hits):
    """Check that requested Rust temporary outputs survive accache invocations."""
    # Pinned sccache caches -Csave-temps but drops its dynamically named
    # bitcode and temporary metadata on a hit. Accache restores every file,
    # including metadata under rustc's randomly named directories.
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

    def normalized(files):
        entries = []
        for name, contents in files.items():
            parts = name.split("/")
            if len(parts) > 2 and parts[1].startswith(("rmeta", "rustc")):
                parts[1] = "rmeta*" if parts[1].startswith("rmeta") else "rustc*"
            entries.append(("/".join(parts), contents))
        return sorted(entries)

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
    assert cold_saved_event["outcome"] == "miss", cold_saved_event
    assert warm_saved_event["outcome"] == "hit", warm_saved_event
    assert accache_saved == accache_warm_saved, sorted(set(accache_saved) ^ set(accache_warm_saved))
    assert normalized(accache_saved) == normalized(direct_saved)
    assert any("/rmeta" in path or "/rustc" in path
               for path in warm_saved_event["artifacts"]), warm_saved_event
    print("PASS oracle rust-save-temps output preservation", flush=True)
    return {"fixture": "rust-save-temps", "revision": 0,
            "oracle_hit": True, "accache": "hit",
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


def check_gcc_nested_specs(root, env, accache, sccache, gcc, hits):
    """Track GCC specs included outside the preprocessor's dependency output."""
    work = root / "gcc-nested-specs"
    work.mkdir()
    specs_dir = root / "gcc-nested-specs-files"
    specs_dir.mkdir()
    (work / "source.S").write_text(".globl answer\nanswer:\n .long VALUE\n")
    top = specs_dir / "top.specs"
    nested = specs_dir / "nested.specs"
    top.write_text(f"%include <{nested}>\n")
    object_file = work / "source.o"
    args = [gcc, "-c", "source.S", "-o", "source.o", "-specs=" + str(top)]

    def compile_object(wrapper):
        object_file.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return completed.stdout, completed.stderr, object_file.read_bytes()

    def preprocessed_source():
        completed = subprocess.run([gcc, "-E", "source.S", "-specs=" + str(top)],
                                   cwd=work, env=env, capture_output=True, timeout=120)
        assert completed.returncode == 0, completed.stderr
        return completed.stdout

    nested.write_text("*asm:\n--defsym=VALUE=1\n")
    original_preprocessed = preprocessed_source()
    direct_old = compile_object([])
    assert compile_object([sccache]) == direct_old
    before_hits = hits()
    assert compile_object([sccache]) == direct_old
    assert hits() > before_hits, "sccache did not hit the original specs action"
    assert compile_object([accache]) == direct_old
    assert compile_object([accache]) == direct_old
    warm_old = json.loads(subprocess.check_output([accache, "explain"], env=env))
    assert warm_old["outcome"] == "hit", warm_old

    nested.write_text("*asm:\n--defsym=VALUE=2\n")
    assert preprocessed_source() == original_preprocessed, "assembler specs changed -E output"
    direct_new = compile_object([])
    assert direct_new[2] != direct_old[2], "nested specs changed no object bytes"
    before_hits = hits()
    assert compile_object([sccache])[2] == direct_old[2], "sccache specs defect changed"
    assert hits() > before_hits, "sccache did not reuse its stale specs action"

    assert compile_object([accache]) == direct_new
    cold_new = json.loads(subprocess.check_output([accache, "explain"], env=env))
    assert cold_new["outcome"] == "miss", cold_new
    assert any("nested.specs" in item for item in cold_new["changes"]), cold_new
    assert compile_object([accache]) == direct_new
    warm_new = json.loads(subprocess.check_output([accache, "explain"], env=env))
    assert warm_new["outcome"] == "hit", warm_new

    print("PASS oracle GCC nested specs invalidation", flush=True)
    return [{"fixture": "gcc-nested-specs", "revision": revision,
             "oracle_hit": True, "accache": "hit",
             "oracle_stale_artifact": revision == 1,
             "artifacts": ["source.o"]} for revision in range(2)]


def check_gcc_profile_note_outputs(root, env, accache, sccache, gcc, hits):
    """Restore a GCC coverage note written to an explicit path."""
    results = []
    cases = [
        ("explicit", ["--coverage", "-fprofile-note=notes/custom.gcno"], True),
        ("last-wins", ["--coverage", "-fprofile-note=notes/old.gcno",
                       "-fprofile-note=notes/custom.gcno"], True),
        ("inactive", ["-fprofile-note=notes/custom.gcno"], False),
    ]
    for name, flags, writes_note in cases:
        work = root / f"gcc-profile-note-{name}"
        work.mkdir()
        (work / "notes").mkdir()
        (work / "source.c").write_text("int answer(void) { return 42; }\n")
        # A fixed seed makes GCC's coverage notes byte-comparable across runs.
        args = [gcc, "-c", "source.c", "-o", "source.o",
                "-frandom-seed=profile-note-" + name, *flags]

        def compile_object(wrapper):
            for path in [work / "source.o", work / "source.gcno",
                         work / "notes/custom.gcno", work / "notes/old.gcno"]:
                path.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            artifacts = {path: contents for path, contents in snapshot(work).items()
                         if path.endswith((".o", ".gcno"))}
            return completed.returncode, completed.stdout, completed.stderr, artifacts

        direct = compile_object([])
        expected = {"source.o", "notes/custom.gcno"} if writes_note else {"source.o"}
        assert direct[0] == 0 and set(direct[3]) == expected, (name, direct[2], direct[3])

        oracle_cold = compile_object([sccache])
        before_hits = hits()
        oracle_warm = compile_object([sccache])
        if writes_note:
            for oracle in [oracle_cold, oracle_warm]:
                assert (oracle[0] == 254
                        and b"failed to zip up compiler outputs" in oracle[2]
                        and oracle[3] == direct[3]), (name, oracle[0], oracle[2][:300])
            assert hits() == before_hits, (name, "sccache cached a failed action")
        else:
            assert oracle_cold == direct and oracle_warm == direct, name
            assert hits() > before_hits, (name, "sccache did not cache the plain object")

        assert compile_object([accache]) == direct, (name, "cold")
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", (name, cold)
        assert compile_object([accache]) == direct, (name, "warm")
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", (name, warm)
        assert set(warm["artifacts"]) == expected, (name, warm)

        results.append({"fixture": "gcc-profile-note-" + name, "revision": 0,
                        "oracle_exit_code": 254 if writes_note else 0,
                        "accache": "hit", "artifacts": sorted(expected)})
        print("PASS oracle GCC profile note", name, flush=True)

    return results


def check_gcc_auto_profile_inputs(root, env, accache, sccache, gcc, hits):
    """Hash GCC AutoFDO profiles that do not appear in preprocessor depfiles."""
    def profile_with_count(hot_count):
        # GCC 16's gcov AutoFDO reader accepts an empty function table. Adding
        # a sampled function makes GCC place its code in .text.hot instead of
        # .text.unlikely, so a stale cache hit changes the object bytes.
        data = struct.pack("<III", 0x67636461, 3, 0)
        data += struct.pack("<I6Q", 0xa8000000, hot_count, hot_count,
                            hot_count, int(bool(hot_count)),
                            int(bool(hot_count)), 16)
        for percentile in range(16):
            data += struct.pack("<IQQ", (percentile + 1) * 62500,
                                hot_count, int(bool(hot_count)))

        if hot_count:
            def gcov_string(value):
                encoded = value.encode() + b"\0"
                return struct.pack("<I", len(encoded)) + encoded

            # Symbol index zero is reserved by GCC's reader. The second
            # symbol names the sampled function and points at source.c.
            data += struct.pack("<III", 0xaa000000, 0, 1)
            data += gcov_string("source.c")
            data += struct.pack("<I", 2)
            data += gcov_string("unused") + struct.pack("<I", 0)
            data += gcov_string("answer") + struct.pack("<I", 0)
            data += struct.pack("<IIIQQIII", 0xac000000, 0, 1,
                                hot_count, 0, 1, 0, 0)
        else:
            data += struct.pack("<IIII", 0xaa000000, 2, 0, 0)
            data += struct.pack("<III", 0xac000000, 1, 0)

        data += struct.pack("<III", 0xae000000, 1, 0)
        return data

    results = []
    for spelling, filename in [("explicit", "sample.afdo"),
                               ("default", "fbdata.afdo")]:
        work = root / f"gcc-auto-profile-{spelling}"
        work.mkdir()
        (work / "source.c").write_text("int answer(void) { return 42; }\n")
        profile = work / filename
        object_file = work / "source.o"
        option = ("-fauto-profile=" + filename if spelling == "explicit"
                  else "-fauto-profile")
        args = [gcc, "-c", "source.c", "-o", "source.o", "-O2",
                "-frandom-seed=auto-profile-" + spelling, option]

        def compile_object(wrapper):
            object_file.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (spelling, wrapper, completed.stderr)
            return completed.stdout, completed.stderr, object_file.read_bytes()

        initial_object = None
        for revision, hot_count in enumerate([0, 100]):
            profile.write_bytes(profile_with_count(hot_count))
            direct = compile_object([])
            if initial_object is None:
                initial_object = direct[2]
            else:
                assert direct[2] != initial_object, (spelling, "profile had no effect")

            before_hits = hits()
            oracle_cold = compile_object([sccache])
            expected_oracle = direct if revision == 0 else (direct[0], direct[1], initial_object)
            assert oracle_cold == expected_oracle, (spelling, revision, "sccache output")
            if revision:
                assert hits() > before_hits, (spelling, "sccache tracked the AutoFDO file")
            else:
                assert hits() == before_hits, (spelling, "unexpected initial sccache hit")
            before_hits = hits()
            assert compile_object([sccache]) == expected_oracle
            assert hits() > before_hits, (spelling, "sccache did not warm-hit")

            assert compile_object([accache]) == direct
            cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert cold["outcome"] == "miss", (spelling, revision, cold)
            if revision:
                assert any(filename in item for item in cold["changes"]), cold
            assert compile_object([accache]) == direct
            warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert warm["outcome"] == "hit", (spelling, revision, warm)

            results.append({"fixture": "gcc-auto-profile-" + spelling,
                            "revision": revision, "oracle_hit": True,
                            "oracle_profile_input_tracked": False,
                            "oracle_stale_object": bool(revision),
                            "accache": "hit", "artifacts": ["source.o"]})
        print("PASS oracle GCC AutoFDO", spelling, "input invalidation", flush=True)

    return results


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


def check_clang_vfs_overlays(root, env, accache, sccache, clang, hits):
    """Track Clang overlay mappings, including edits invisible to depfiles."""
    results = []
    for fixture, option in [
        ("clang-ivfs-overlay", ["-ivfsoverlay", "overlay.json"]),
        ("clang-ivfs-overlay-joined", ["-ivfsoverlayoverlay.json"]),
        ("clang-vfs-overlay", ["-vfsoverlay", "overlay.json"]),
        ("clang-long-vfs-overlay", ["--vfsoverlay", "overlay.json"]),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "source.c").write_text(
            "#include <value.h>\nint answer(void) { return VALUE; }\n")
        (work / "first.h").write_text("#define VALUE 42\n")
        (work / "second.h").write_text("#define VALUE 73\n")
        overlay = work / "overlay.json"
        object_file = work / "source.o"
        virtual = work / "virtual"
        args = [clang, "-c", "source.c", "-o", "source.o", "-I" + str(virtual),
                *option]

        def compile_object(wrapper):
            object_file.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return completed.stdout, completed.stderr, object_file.read_bytes()

        previous_object = None
        previous_objects = []
        for revision, header in enumerate(["first.h", "second.h", "second.h"]):
            data = {"version": 0, "roots": [{
                "type": "directory", "name": str(virtual),
                "contents": [{"type": "file", "name": "value.h",
                              "external-contents": str(work / header)}],
            }]}
            # The final edit leaves the selected header and preprocessed C
            # unchanged, but the overlay file remains a compiler input.
            overlay.write_text(json.dumps(data, indent=2 if revision == 2 else None))
            direct = compile_object([])
            if revision == 1:
                assert direct[2] != previous_object, (fixture, "mapping changed no object bytes")
            if revision == 2:
                assert direct[2] == previous_object, (fixture, "formatting changed the object")
            previous_object = direct[2]

            before_hits = hits()
            oracle_cold = compile_object([sccache])
            oracle_hit = hits() > before_hits
            if oracle_cold != direct:
                assert (revision > 0 and oracle_hit
                        and oracle_cold[2] != direct[2]
                        and oracle_cold[2] in previous_objects), (
                    fixture, revision, "unexpected sccache difference")
            before_hits = hits()
            assert compile_object([sccache]) == oracle_cold
            assert hits() > before_hits, (fixture, revision, "sccache did not warm-hit")

            assert compile_object([accache]) == direct
            cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            if revision:
                assert any("overlay.json" in item for item in cold["changes"]), cold
            assert compile_object([accache]) == direct
            warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)
            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": True, "oracle_stale_artifact": oracle_cold != direct,
                            "accache": "hit", "artifacts": ["source.o"]})
            previous_objects.append(direct[2])

        print("PASS oracle", fixture, "overlay invalidation", flush=True)
    return results


def check_clang_profile_use(root, env, accache, sccache, clang, hits):
    """Track the profile data consumed by a cacheable Clang action."""
    source = (
        "__attribute__((noinline)) int slow(int x) {\n"
        "    volatile int y = x;\n"
        "    for (int i = 0; i < 3; ++i) y += i;\n"
        "    return y;\n"
        "}\n"
        "int branch(int x) { if (x > 100) return slow(x); return x + 1; }\n"
        "int main(int argc, char **argv) { return branch(argc); }\n")
    generator = root / "clang-profile-generator"
    generator.mkdir()
    (generator / "source.c").write_text(source)
    subprocess.run([clang, "-O2", "-fprofile-instr-generate", "source.c", "-o", "program"],
                   cwd=generator, env=env, check=True, capture_output=True)
    profdata = str(Path(clang).with_name("llvm-profdata"))
    profiles = []
    for name, arguments in [("low", []), ("high", ["x"] * 150)]:
        raw = generator / (name + ".profraw")
        subprocess.run([str(generator / "program"), *arguments], cwd=generator,
                       env=env | {"LLVM_PROFILE_FILE": str(raw)}, capture_output=True,
                       timeout=120)
        merged = generator / (name + ".profdata")
        subprocess.run([profdata, "merge", "-o", str(merged), str(raw)], cwd=generator,
                       env=env, check=True, capture_output=True)
        profiles.append(merged.read_bytes())
    assert profiles[0] != profiles[1], "profile runs produced identical input data"

    results = []
    for fixture, option, filename in [
        ("clang-profile-use", "-fprofile-instr-use=profile.profdata", "profile.profdata"),
        ("clang-profile-instr-default", "-fprofile-instr-use", "default.profdata"),
        ("clang-profile-use-directory", "-fprofile-use=.", "default.profdata"),
        ("clang-profile-use-default", "-fprofile-use", "default.profdata"),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "source.c").write_text(source)
        object_file = work / "source.o"
        profile_file = work / filename
        args = [clang, "-O2", "-c", "source.c", option, "-o", "source.o"]

        def compile_object(wrapper):
            object_file.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return completed.stdout, completed.stderr, object_file.read_bytes()

        initial_object = None
        for revision, profile in enumerate(profiles):
            profile_file.write_bytes(profile)
            direct = compile_object([])
            if initial_object is None:
                initial_object = direct[2]
            else:
                assert direct[2] != initial_object, (fixture, "profile had no effect")
            before_cold_hits = hits()
            assert compile_object([sccache]) == direct
            assert hits() == before_cold_hits, (fixture, "sccache ignored the changed profile")
            before_hits = hits()
            assert compile_object([sccache]) == direct
            assert hits() > before_hits, (fixture, "sccache did not hit the profile action")

            assert compile_object([accache]) == direct
            cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert cold["outcome"] == "miss", (fixture, cold)
            if revision:
                assert any(filename in item for item in cold["changes"]), (fixture, cold)
            assert compile_object([accache]) == direct
            warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert warm["outcome"] == "hit", (fixture, warm)
            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": True, "accache": "hit", "artifacts": ["source.o"]})

        print("PASS oracle Clang", fixture, "input invalidation", flush=True)
    return results


def check_clang_sanitizer_ignorelist(root, env, accache, sccache, clang, hits):
    """Invalidate a sanitized object when its ignorelist changes."""
    results = []
    for fixture, option in [
        ("clang-sanitizer-ignorelist", "-fsanitize-ignorelist=ignorelist.txt"),
        ("clang-sanitizer-blacklist", "-fsanitize-blacklist=ignorelist.txt"),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "source.c").write_text("int checked(int a, int b) { return a + b; }\n")
        ignorelist = work / "ignorelist.txt"
        object_file = work / "source.o"
        args = [clang, "-O1", "-c", "source.c", "-fsanitize=signed-integer-overflow",
                option, "-o", "source.o"]

        def compile_object(wrapper):
            object_file.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return completed.stdout, completed.stderr, object_file.read_bytes()

        original_object = None
        for revision, contents in enumerate(["# empty\n", "fun:checked\n"]):
            ignorelist.write_text(contents)
            direct = compile_object([])
            if original_object is None:
                original_object = direct[2]
            else:
                assert direct[2] != original_object, (fixture, "ignorelist edit had no effect")

            before_hits = hits()
            assert compile_object([sccache]) == direct
            assert hits() == before_hits, (fixture, "sccache ignored the changed ignorelist")
            before_hits = hits()
            assert compile_object([sccache]) == direct
            assert hits() > before_hits, (fixture, "sccache did not warm-hit")

            assert compile_object([accache]) == direct
            cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            if revision:
                assert any("ignorelist.txt" in item for item in cold["changes"]), cold
            assert compile_object([accache]) == direct
            warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)
            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": True, "accache": "hit",
                            "artifacts": ["source.o"]})

        print("PASS oracle", fixture, "ignorelist invalidation", flush=True)
    return results


def check_clang_xray_lists(root, env, accache, sccache, clang, hits):
    """Track all three XRay attribute-list inputs and their depfiles."""
    results = []
    for fixture, option, threshold, selected in [
        ("clang-xray-always", "-fxray-always-instrument", "1000", "fun:sampled\n"),
        ("clang-xray-never", "-fxray-never-instrument", "1", "fun:sampled\n"),
        ("clang-xray-attrs", "-fxray-attr-list", "1000",
         "[always]\nfun:sampled\n"),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "source.c").write_text(
            "__attribute__((noinline)) int sampled(int x) { return x + 1; }\n")
        list_file = work / "list.txt"
        object_file = work / "source.o"
        depfile = work / "source.d"
        args = [clang, "-O1", "-c", "source.c", "-fxray-instrument",
                "-fxray-instruction-threshold=" + threshold,
                option + "=list.txt", "-MD", "-MF", "source.d", "-o", "source.o"]

        def compile_object(wrapper):
            object_file.unlink(missing_ok=True)
            depfile.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return (completed.stdout, completed.stderr,
                    object_file.read_bytes(), depfile.read_bytes())

        first_object = None
        for revision, contents in enumerate(["# no entries\n", selected]):
            list_file.write_text(contents)
            direct = compile_object([])
            assert b"list.txt" in direct[3], (fixture, "dep-info omitted XRay list")
            if first_object is None:
                first_object = direct[2]
            else:
                assert direct[2] != first_object, (fixture, "XRay list edit had no effect")

            before_hits = hits()
            assert compile_object([sccache]) == direct
            assert hits() == before_hits, (fixture, "sccache ignored the changed list")
            before_hits = hits()
            assert compile_object([sccache]) == direct
            assert hits() > before_hits, (fixture, "sccache did not warm-hit")

            assert compile_object([accache]) == direct
            cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            if revision:
                assert any("list.txt" in item for item in cold["changes"]), cold
            assert compile_object([accache]) == direct
            warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)
            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": True, "accache": "hit",
                            "artifacts": ["source.o", "source.d"]})

        print("PASS oracle", fixture, "XRay list invalidation", flush=True)
    return results


def check_clang_profile_list(root, env, accache, sccache, clang, hits):
    """Invalidate profile instrumentation when its selection list changes."""
    work = root / "clang-profile-list"
    work.mkdir()
    (work / "source.c").write_text(
        "__attribute__((noinline)) int tracked(int x) { return x + 1; }\n"
        "__attribute__((noinline)) int other(int x) { return x + 2; }\n")
    list_file = work / "list.txt"
    object_file = work / "source.o"
    depfile = work / "source.d"
    args = [clang, "-O1", "-c", "source.c", "-fprofile-instr-generate",
            "-fprofile-list=list.txt", "-MD", "-MF", "source.d",
            "-o", "source.o"]

    def compile_object(wrapper):
        object_file.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return (completed.stdout, completed.stderr,
                object_file.read_bytes(), depfile.read_bytes())

    results = []
    first_object = None
    for revision, contents in enumerate(["fun:tracked\n", "fun:other\n"]):
        list_file.write_text(contents)
        direct = compile_object([])
        assert b"list.txt" in direct[3], "profile list absent from dep-info"
        if first_object is None:
            first_object = direct[2]
        else:
            assert direct[2] != first_object, "profile list edit had no effect"

        before_hits = hits()
        oracle = compile_object([sccache])
        if revision:
            # The pinned frontend does not classify this accepted Clang option
            # as a file input, so its warm hit returns the prior object.
            assert oracle[:2] == direct[:2] and oracle[3] == direct[3]
            assert oracle[2] == first_object != direct[2]
            assert hits() > before_hits, "sccache did not reuse its stale object"
        else:
            assert oracle == direct
            assert hits() == before_hits, "sccache unexpectedly warm-hit"
        before_hits = hits()
        assert compile_object([sccache]) == oracle
        assert hits() > before_hits, "sccache did not warm-hit"

        assert compile_object([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", (revision, cold)
        if revision:
            assert any("list.txt" in item for item in cold["changes"]), cold
        assert compile_object([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", (revision, warm)
        results.append({"fixture": "clang-profile-list", "revision": revision,
                        "oracle_hit": True, "oracle_stale_artifact": bool(revision),
                        "accache": "hit",
                        "artifacts": ["source.o", "source.d"]})

    print("PASS oracle clang-profile-list invalidation", flush=True)
    return results


def check_clang_sample_profile(root, env, accache, sccache, clang, hits):
    """Invalidate a sample-guided object when its unlisted profile changes."""
    fixture = "clang-sample-profile"
    work = root / fixture
    work.mkdir()
    (work / "source.c").write_text(
        "int hot(int x) { return x * 7 + 3; }\n"
        "int cold(int x) { return x / 7 + 3; }\n"
        "int answer(int x) {\n"
        "  if (x > 0) return hot(x);\n"
        "  return cold(x);\n"
        "}\n")
    profile = work / "sample.prof"
    object_file = work / "source.o"
    depfile = work / "source.d"
    args = [clang, "-O2", "-gline-tables-only", "-c", "source.c",
            "-fprofile-sample-use=sample.prof", "-MD", "-MF", "source.d",
            "-o", "source.o"]

    def compile_object(wrapper):
        object_file.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
        return (completed.stdout, completed.stderr,
                object_file.read_bytes(), depfile.read_bytes())

    first_object = None
    results = []
    for revision, counts in enumerate([(999999, 1), (1, 999999)]):
        profile.write_text(
            f"answer:1000000:0\n 1: {counts[0]}\n 2: {counts[1]}\n")
        direct = compile_object([])
        assert b"sample.prof" not in direct[3], (fixture, "profile appeared in dep-info")
        if first_object is None:
            first_object = direct[2]
            assert compile_object([sccache]) == direct, (fixture, "oracle cold")
        else:
            assert direct[2] != first_object, (fixture, "profile edit had no effect")
            before_hits = hits()
            oracle = compile_object([sccache])
            assert hits() > before_hits, (fixture, "oracle did not reuse its stale action")
            assert oracle[2] == first_object, (fixture, "oracle defect changed")

        before_hits = hits()
        assert compile_object([sccache])[2] == first_object, (fixture, "oracle warm")
        assert hits() > before_hits, (fixture, "oracle did not hit")

        assert compile_object([accache]) == direct, (fixture, revision, "cold")
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", (fixture, revision, cold)
        if revision:
            assert any("sample.prof" in item for item in cold["changes"]), cold
        assert compile_object([accache]) == direct, (fixture, revision, "warm")
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", (fixture, revision, warm)

        results.append({"fixture": fixture, "revision": revision,
                        "oracle_hit": True, "accache": "hit",
                        "oracle_stale_artifact": revision == 1,
                        "artifacts": ["source.o", "source.d"]})

    print("PASS oracle", fixture, "sample profile invalidation", flush=True)
    return results


def check_clang_multilib_config(root, env, accache, sccache, clang, hits):
    """Track an explicit multilib YAML file and its selected header tree."""
    fixture = "clang-multilib-config"
    work = root / fixture
    work.mkdir()
    sysroot = work / "sysroot"
    for variant, value in [("variantA", 42), ("variantB", 73)]:
        include = sysroot / variant / "include"
        include.mkdir(parents=True)
        (include / "value.h").write_text(f"#define VALUE {value}\n")
    (work / "source.c").write_text(
        "#include <value.h>\nint answer(void) { return VALUE; }\n")
    config = work / "multilib.yaml"
    object_file = work / "source.o"
    depfile = work / "source.d"
    args = [clang, "--target=aarch64-none-elf", "--sysroot=" + str(sysroot),
            "-multi-lib-config=multilib.yaml", "-c", "source.c",
            "-o", "source.o", "-MD", "-MF", "source.d"]

    def compile_object(wrapper):
        object_file.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
        return (completed.stdout, completed.stderr,
                object_file.read_bytes(), depfile.read_bytes())

    results = []
    first_object = None
    first_direct = None
    previous = None
    for revision, (variant, comment) in enumerate([
        ("variantA", ""), ("variantB", ""),
        ("variantB", "# same selected variant\n"),
    ]):
        config.write_text(
            "MultilibVersion: 1.0\nVariants:\n"
            f"- Dir: {variant}\n"
            "  Flags: [--target=aarch64-unknown-none-elf]\n" + comment)
        direct = compile_object([])
        assert variant.encode() in direct[3], (fixture, revision, "wrong header selected")
        assert b"multilib.yaml" not in direct[3], (fixture, "config entered dep-info")
        if first_object is None:
            first_object = direct[2]
            first_direct = direct
        elif revision == 1:
            assert direct[2] != first_object, (fixture, "variant changed no object bytes")
        else:
            assert direct == previous, (fixture, "comment changed compiler output")

        before_hits = hits()
        oracle = compile_object([sccache])
        if revision:
            assert hits() > before_hits, (fixture, "oracle did not reuse its stale action")
            assert oracle == first_direct, (fixture, revision, "oracle defect changed")
        else:
            assert oracle == direct, (fixture, revision, "oracle cold")
        before_hits = hits()
        assert compile_object([sccache]) == oracle, (fixture, revision, "oracle warm")
        assert hits() > before_hits, (fixture, revision, "oracle did not hit")

        assert compile_object([accache]) == direct, (fixture, revision, "cold")
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", (fixture, revision, cold)
        if revision:
            assert any("multilib.yaml" in item for item in cold["changes"]), cold
        assert compile_object([accache]) == direct, (fixture, revision, "warm")
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", (fixture, revision, warm)

        results.append({"fixture": fixture, "revision": revision,
                        "oracle_hit": True, "accache": "hit",
                        "oracle_stale_artifact": revision > 0,
                        "artifacts": ["source.o", "source.d"]})
        previous = direct

    print("PASS oracle", fixture, "configuration invalidation", flush=True)
    return results


def check_clang_profile_remapping(root, env, accache, sccache, clang, hits):
    """Track C++ profile remappings even though Clang omits them from dep-info."""
    source = (
        "namespace NS { __attribute__((noinline)) int hot(int x) {\n"
        "    if (x > 100) return x * 3;\n"
        "    return x + 7;\n"
        "} }\n"
        "int main(int argc, char **) {\n"
        "    int result = 0;\n"
        "    for (int i = 0; i < 1000; ++i) result += NS::hot(argc + i);\n"
        "    return result & 7;\n"
        "}\n")
    generator = root / "clang-profile-remap-generator"
    generator.mkdir()
    (generator / "old.cc").write_text(source.replace("NS", "old"))
    subprocess.run([clang, "-O2", "-fprofile-instr-generate", "old.cc",
                    "-o", "program"], cwd=generator, env=env,
                   check=True, capture_output=True)
    raw_profile = generator / "run.profraw"
    subprocess.run([str(generator / "program")], cwd=generator,
                   env=env | {"LLVM_PROFILE_FILE": str(raw_profile)},
                   capture_output=True, timeout=120)
    assert raw_profile.is_file(), "instrumented program produced no profile"
    profile = generator / "profile.profdata"
    profdata = str(Path(clang).with_name("llvm-profdata"))
    subprocess.run([profdata, "merge", "-o", str(profile), str(raw_profile)],
                   cwd=generator, env=env, check=True, capture_output=True)

    work = root / "clang-profile-remapping"
    work.mkdir()
    (work / "new.cc").write_text(source.replace("NS", "newer"))
    (work / "profile.profdata").write_bytes(profile.read_bytes())
    remapping = work / "remap.txt"
    object_file = work / "source.o"
    depfile = work / "source.d"
    args = [clang, "-O2", "-c", "new.cc",
            "-fprofile-instr-use=profile.profdata",
            "-fprofile-remapping-file=remap.txt",
            "-MD", "-MF", "source.d", "-o", "source.o"]

    def compile_object(wrapper):
        object_file.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return (completed.stdout, completed.stderr,
                object_file.read_bytes(), depfile.read_bytes())

    results = []
    first_object = None
    for revision, contents in enumerate(["# no remappings\n",
                                         "name 3old 5newer\n"]):
        remapping.write_text(contents)
        direct = compile_object([])
        assert b"remap.txt" not in direct[3], "remapping unexpectedly in dep-info"
        if first_object is None:
            first_object = direct[2]
        else:
            assert direct[2] != first_object, "remapping edit had no effect"

        before_hits = hits()
        assert compile_object([sccache]) == direct
        assert hits() == before_hits, "sccache ignored the changed remapping"
        before_hits = hits()
        assert compile_object([sccache]) == direct
        assert hits() > before_hits, "sccache did not warm-hit"

        assert compile_object([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", (revision, cold)
        if revision:
            assert any("remap.txt" in item for item in cold["changes"]), cold
        assert compile_object([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", (revision, warm)
        results.append({"fixture": "clang-profile-remapping", "revision": revision,
                        "oracle_hit": True, "accache": "hit",
                        "artifacts": ["source.o", "source.d"]})

    print("PASS oracle clang-profile-remapping invalidation", flush=True)
    return results


def check_clang_layout_seed(root, env, accache, sccache, clang, hits):
    """Track a layout seed file omitted from Clang's dependency output."""
    work = root / "clang-layout-seed"
    work.mkdir()
    (work / "source.c").write_text(
        "struct __attribute__((randomize_layout)) S { int a,b,c,d,e,f,g,h,i,j,k,l; };\n"
        "int offsets(void) { return __builtin_offsetof(struct S,a)"
        "+2*__builtin_offsetof(struct S,b)+3*__builtin_offsetof(struct S,c); }\n")
    seed_file = work / "seed.txt"
    object_file = work / "source.o"
    depfile = work / "source.d"
    args = [clang, "-O2", "-c", "source.c",
            "-frandomize-layout-seed-file=seed.txt", "-MD", "-MF", "source.d",
            "-o", "source.o"]

    def compile_object(wrapper):
        object_file.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return (completed.stdout, completed.stderr,
                object_file.read_bytes(), depfile.read_bytes())

    results = []
    first_object = None
    for revision, seed in enumerate(["0123456789abcdef", "fedcba9876543210"]):
        seed_file.write_text(seed + "\n")
        direct = compile_object([])
        assert b"seed.txt" not in direct[3], "dep-info listed layout seed"
        if first_object is None:
            first_object = direct[2]
        else:
            assert direct[2] != first_object, "layout seed edit had no effect"

        before_hits = hits()
        assert compile_object([sccache]) == direct
        assert hits() == before_hits, "sccache ignored the changed layout seed"
        before_hits = hits()
        assert compile_object([sccache]) == direct
        assert hits() > before_hits, "sccache did not warm-hit"

        assert compile_object([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", (revision, cold)
        if revision:
            assert any("seed.txt" in item for item in cold["changes"]), cold
        assert compile_object([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", (revision, warm)
        results.append({"fixture": "clang-layout-seed", "revision": revision,
                        "oracle_hit": True, "accache": "hit",
                        "artifacts": ["source.o", "source.d"]})

    print("PASS oracle clang-layout-seed input invalidation", flush=True)
    return results


def check_clang_warning_mappings(root, env, accache, sccache, clang, hits):
    """Invalidate cached diagnostics when a suppression mapping changes."""
    work = root / "clang-warning-mappings"
    work.mkdir()
    (work / "source.c").write_text(
        "int answer(void) { int unused; return 42; }\n")
    mapping_file = work / "mappings.txt"
    object_file = work / "source.o"
    depfile = work / "source.d"
    args = [clang, "-c", "source.c", "-o", "source.o", "-Wunused-variable",
            "--warning-suppression-mappings=mappings.txt", "-MD", "-MF", "source.d"]

    def compile_object(wrapper):
        object_file.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return (completed.stdout, completed.stderr,
                object_file.read_bytes(), depfile.read_bytes())

    results = []
    first_object = None
    for revision, contents in enumerate(["# no suppression\n",
                                         "[unused-variable]\nsrc:*\n"]):
        mapping_file.write_text(contents)
        direct = compile_object([])
        assert b"mappings.txt" not in direct[3], "dep-info listed warning mapping"
        assert (b"unused variable" in direct[1]) == (revision == 0), direct[1]
        if first_object is None:
            first_object = direct[2]
        else:
            assert direct[2] == first_object, "mapping edit changed object bytes"

        before_hits = hits()
        assert compile_object([sccache]) == direct
        assert hits() == before_hits, "sccache ignored the changed mapping"
        before_hits = hits()
        assert compile_object([sccache]) == direct
        assert hits() > before_hits, "sccache did not warm-hit"

        assert compile_object([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", (revision, cold)
        if revision:
            assert any("mappings.txt" in item for item in cold["changes"]), cold
        assert compile_object([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", (revision, warm)
        results.append({"fixture": "clang-warning-mappings", "revision": revision,
                        "oracle_hit": True, "accache": "hit",
                        "artifacts": ["source.o", "source.d"]})

    print("PASS oracle clang-warning-mappings diagnostic invalidation", flush=True)
    return results


def check_rust_native_archives(root, env, accache, sccache, gcc, rustc, hits):
    """Hash native archives for joined and separated Rust library flags."""
    results = []
    ar = str(Path(gcc).with_name("ar"))
    for fixture, flags in [
        ("rust-native-archive", ["-Lnative=.", "-lstatic=native"]),
        ("rust-native-archive-split-search", ["-L", "native=.", "-lstatic=native"]),
        ("rust-native-archive-split-library", ["-Lnative=.", "-l", "static=native"]),
        ("rust-native-archive-split-both", ["-L", "native=.", "-l", "static=native"]),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "target").mkdir()
        (work / "native.rs").write_text(
            'unsafe extern "C" { pub fn native() -> i32; }\n')
        archive = work / "libnative.a"
        library = work / "target/libnative_example.rlib"
        depfile = work / "target/native_example.d"
        args = [rustc, "--crate-name", "native_example", "--crate-type", "rlib",
                "--emit=link,dep-info", "--out-dir", "target", *flags, "native.rs"]

        def compile_library(wrapper):
            library.unlink(missing_ok=True)
            depfile.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return (completed.stdout, completed.stderr,
                    library.read_bytes(), depfile.read_bytes())

        initial_library = None
        for revision, value in enumerate([23, 31]):
            (work / "native.c").write_text(
                f"int native(void) {{ return {value}; }}\n")
            subprocess.run([gcc, "-c", "native.c", "-o", "native.o"], cwd=work,
                           env=env, check=True, capture_output=True)
            subprocess.run([ar, "crs", str(archive), "native.o"], cwd=work,
                           env=env, check=True, capture_output=True)

            direct = compile_library([])
            if initial_library is None:
                initial_library = direct[2]
            else:
                assert direct[2] != initial_library, (fixture, "archive had no effect")

            before_hits = hits()
            oracle_cold = compile_library([sccache])
            oracle_hit = hits() > before_hits
            if oracle_cold != direct:
                assert (revision == 1 and oracle_hit
                        and oracle_cold[2] == initial_library), (
                    fixture, "unexpected sccache difference")
            before_hits = hits()
            assert compile_library([sccache]) == oracle_cold
            assert hits() > before_hits, (fixture, "sccache did not warm-hit")

            assert compile_library([accache]) == direct
            cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            if revision:
                assert any("libnative.a" in item for item in cold["changes"]), cold
            assert compile_library([accache]) == direct
            warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)
            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": True, "oracle_stale_artifact": oracle_cold != direct,
                            "accache": "hit",
                            "artifacts": ["target/libnative_example.rlib",
                                          "target/native_example.d"]})

        print("PASS oracle", fixture, "archive invalidation", flush=True)
    return results


def check_rust_extern_inputs(root, env, accache, sccache, rustc, hits):
    """Hash explicit extern crates and preserve bare-extern passthrough."""
    results = []
    for fixture, flags in [
        ("rust-extern-path", ["--extern", "dep=libdep.rlib"]),
        ("rust-extern-path-joined", ["--extern=dep=libdep.rlib"]),
        ("rust-extern-search", ["--extern", "dep", "-Lcrate=."]),
        ("rust-extern-search-split", ["--extern=dep", "-L", "crate=."]),
    ]:
        cacheable = fixture.startswith("rust-extern-path")
        work = root / fixture
        work.mkdir()
        (work / "target").mkdir()
        source_dir = root / (fixture + "-dependency-source")
        source_dir.mkdir()
        dependency_source = source_dir / "dep.rs"
        (work / "consumer.rs").write_text(
            "extern crate dep; pub fn answer() -> u32 { dep::VALUE }\n")
        library = work / "target/libconsumer.rlib"
        depfile = work / "target/consumer.d"
        args = [rustc, "--crate-name=consumer", "--crate-type=rlib",
                "--emit=link,dep-info", "--out-dir=target", *flags, "consumer.rs"]

        def compile_consumer(wrapper):
            library.unlink(missing_ok=True)
            depfile.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return (completed.stdout, completed.stderr,
                    library.read_bytes(), depfile.read_bytes())

        initial_library = None
        for revision, value in enumerate([42, 73]):
            dependency_source.write_text(f"pub const VALUE: u32 = {value};\n")
            subprocess.run([rustc, "--crate-name=dep", "--crate-type=rlib",
                            str(dependency_source), "-o", "libdep.rlib"],
                           cwd=work, env=env, check=True, capture_output=True)

            direct = compile_consumer([])
            assert b"libdep.rlib" not in direct[3], (fixture, "dep-info listed extern rlib")
            if initial_library is None:
                initial_library = direct[2]
            else:
                assert direct[2] != initial_library, (fixture, "extern had no effect")

            before_hits = hits()
            oracle_cold = compile_consumer([sccache])
            if cacheable:
                oracle_hit = hits() > before_hits
                if oracle_cold != direct:
                    assert (revision == 1 and oracle_hit
                            and oracle_cold[2] == initial_library), (
                        fixture, "unexpected sccache difference")
                before_hits = hits()
                assert compile_consumer([sccache]) == oracle_cold
                assert hits() > before_hits, (fixture, "sccache did not warm-hit")

                assert compile_consumer([accache]) == direct
                cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
                assert cold["outcome"] == "miss", (fixture, revision, cold)
                if revision:
                    assert any("libdep.rlib" in item for item in cold["changes"]), cold
                assert compile_consumer([accache]) == direct
                warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
                assert warm["outcome"] == "hit", (fixture, revision, warm)
            else:
                assert oracle_cold == direct and hits() == before_hits, fixture
                assert compile_consumer([sccache]) == direct
                assert hits() == before_hits, (fixture, "sccache cached a bare extern")
                for _ in range(2):
                    assert compile_consumer([accache]) == direct
                    event = json.loads(subprocess.check_output([accache, "explain"], env=env))
                    assert (event["outcome"] == "bypass"
                            and "no path for extern" in event["reason"]), (fixture, event)

            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": cacheable,
                            "oracle_stale_artifact": oracle_cold != direct,
                            "accache": "hit" if cacheable else "bypass",
                            "artifacts": ["target/libconsumer.rlib", "target/consumer.d"]})

        print("PASS oracle", fixture, "extern invalidation", flush=True)
    return results


def check_rust_target_json(root, env, accache, sccache, rustc, hits):
    """Hash a custom Rust target spec absent from rustc dep-info."""
    rust_env = env | {"RUSTC_BOOTSTRAP": "1"}
    version = subprocess.run([rustc, "-vV"], env=rust_env, check=True,
                             capture_output=True, text=True)
    host = next(line.removeprefix("host: ") for line in version.stdout.splitlines()
                if line.startswith("host: "))
    target = subprocess.run([rustc, "-Zunstable-options", "--print", "target-spec-json",
                             "--target", host], env=rust_env, check=True, capture_output=True)
    specification = json.loads(target.stdout)
    original_cpu = specification["cpu"]
    changed_cpu = "generic" if original_cpu != "generic" else "cortex-a72"

    source = (
        "#![allow(internal_features)]\n"
        "#![feature(no_core, lang_items, rustc_attrs)]\n"
        "#![no_core]\n"
        '#[lang = "pointee_sized"] #[rustc_coinductive] pub trait PointeeSized {}\n'
        '#[lang = "meta_sized"] #[rustc_coinductive] pub trait MetaSized: PointeeSized {}\n'
        '#[lang = "sized"] #[rustc_coinductive] pub trait Sized: MetaSized {}\n'
        "pub fn answer() -> u32 { 42 }\n"
    )
    results = []
    for fixture, target_flags in [
        ("rust-target-json", ["--target", "host-target.json"]),
        ("rust-target-json-joined", ["--target=host-target.json"]),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "target").mkdir()
        (work / "library.rs").write_text(source)
        spec_file = work / "host-target.json"
        library = work / "target/libexample.rlib"
        depfile = work / "target/example.d"
        args = [rustc, "-Zunstable-options", "--crate-name=example",
                "--crate-type=rlib", "--emit=link,dep-info", "--out-dir=target",
                "-Copt-level=3", *target_flags, "library.rs"]

        def compile_library(wrapper):
            library.unlink(missing_ok=True)
            depfile.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=rust_env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return (completed.stdout, completed.stderr,
                    library.read_bytes(), depfile.read_bytes())

        original_library = None
        for revision, cpu in enumerate([original_cpu, changed_cpu]):
            spec_file.write_text(json.dumps(specification | {"cpu": cpu}))
            direct = compile_library([])
            assert b"host-target.json" not in direct[3], (fixture, "dep-info listed target spec")
            if original_library is None:
                original_library = direct[2]
            else:
                assert direct[2] != original_library, (fixture, "CPU edit had no effect")

            before_hits = hits()
            oracle_cold = compile_library([sccache])
            oracle_hit = hits() > before_hits
            if oracle_cold != direct:
                assert (revision == 1 and oracle_hit
                        and oracle_cold[2] == original_library), (
                    fixture, "unexpected sccache difference")
            before_hits = hits()
            assert compile_library([sccache]) == oracle_cold
            assert hits() > before_hits, (fixture, "sccache did not warm-hit")

            assert compile_library([accache]) == direct
            cold = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            if revision:
                assert any("host-target.json" in item for item in cold["changes"]), cold
            assert compile_library([accache]) == direct
            warm = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)
            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": True, "oracle_stale_artifact": oracle_cold != direct,
                            "accache": "hit",
                            "artifacts": ["target/libexample.rlib", "target/example.d"]})

        print("PASS oracle", fixture, "target-spec invalidation", flush=True)
    return results


def build_llvm_stamp_plugin(work, clang, env, stamp):
    """Build the same pass-plugin path with a different object-level stamp."""
    source = work / "stamp.cpp"
    if not source.exists():
        source.write_text('''\
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
using namespace llvm;
struct StampPass : PassInfoMixin<StampPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    auto *Type = Type::getInt32Ty(M.getContext());
    new GlobalVariable(M, Type, true, GlobalValue::ExternalLinkage,
                       ConstantInt::get(Type, STAMP), "accache_plugin_stamp");
    return PreservedAnalyses::none();
  }
};
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "accache-oracle", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback([](ModulePassManager &MPM, OptimizationLevel) {
              MPM.addPass(StampPass());
            });
          }};
}
''')
    llvm = Path(clang).parent
    flags = subprocess.check_output([str(llvm / "llvm-config"), "--cxxflags",
                                     "--ldflags", "--libs", "core", "passes"],
                                    env=env, text=True)
    build = subprocess.run([str(llvm / "clang++"), "-shared", "-fPIC",
                            f"-DSTAMP={stamp}", *shlex.split(flags),
                            "stamp.cpp", "-o", "plugin.so"],
                           cwd=work, env=env, capture_output=True, timeout=120)
    assert build.returncode == 0, build.stderr
    return work / "plugin.so"


def check_clang_pass_plugin(root, env, accache, sccache, clang, hits):
    """Invalidate a Clang object when its LLVM pass plugin changes."""
    work = root / "clang-pass-plugin"
    work.mkdir()
    (work / "source.c").write_text("int answer(void) { return 42; }\n")
    plugin = work / "plugin.so"
    object_file = work / "source.o"
    args = [clang, "-O2", "-c", "source.c", "-fpass-plugin=" + str(plugin),
            "-o", "source.o"]

    def compile_object(wrapper):
        object_file.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return completed.stdout, completed.stderr, object_file.read_bytes()

    results = []
    first_object = None
    for revision, stamp in enumerate([1, 2]):
        build_llvm_stamp_plugin(work, clang, env, stamp)
        direct = compile_object([])
        if first_object is None:
            first_object = direct[2]
        else:
            assert direct[2] != first_object, "Clang plugin edit had no effect"

        before_hits = hits()
        assert compile_object([sccache]) == direct
        assert hits() == before_hits, "sccache ignored the changed Clang plugin"
        before_hits = hits()
        assert compile_object([sccache]) == direct
        assert hits() > before_hits, "sccache did not warm-hit"

        assert compile_object([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert cold["outcome"] == "miss", (revision, cold)
        if revision:
            assert any("plugin.so" in item for item in cold["changes"]), cold
        assert compile_object([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert warm["outcome"] == "hit", (revision, warm)
        results.append({"fixture": "clang-pass-plugin", "revision": revision,
                        "oracle_hit": True, "accache": "hit",
                        "artifacts": ["source.o"]})

    print("PASS oracle clang-pass-plugin input invalidation", flush=True)
    return results


def check_clang_frontend_plugin(root, env, accache, sccache, clang, hits):
    """Replay a Clang AST plugin diagnostic after its library changes."""
    llvm = Path(clang).parent
    flags = subprocess.check_output([str(llvm / "llvm-config"), "--cxxflags",
                                     "--ldflags", "--libs", "core"],
                                    env=env, text=True)
    plugin_source = '''\
#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#define STR2(x) #x
#define STR(x) STR2(x)
using namespace clang;
class StampConsumer : public ASTConsumer {
 public:
  void HandleTranslationUnit(ASTContext &Context) override {
    auto &Diags = Context.getDiagnostics();
    unsigned Id = Diags.getCustomDiagID(DiagnosticsEngine::Warning,
                                         "accache stamp " STR(STAMP_VALUE));
    Diags.Report(Id);
  }
};
class StampAction : public PluginASTAction {
 protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &, llvm::StringRef) override {
    return std::make_unique<StampConsumer>();
  }
  bool ParseArgs(const CompilerInstance &, const std::vector<std::string> &) override {
    return true;
  }
  ActionType getActionType() override { return AddBeforeMainAction; }
};
static FrontendPluginRegistry::Add<StampAction> X("accache-stamp", "accache test plugin");
'''
    results = []
    for fixture, plugin_flags in [
        ("clang-frontend-plugin", lambda path: ["-fplugin=" + str(path)]),
        ("clang-xclang-load", lambda path: [
            "-Xclang", "-load", "-Xclang", str(path),
            "-Xclang", "-add-plugin", "-Xclang", "accache-stamp"]),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "source.c").write_text("int answer(void) { return 42; }\n")
        (work / "stamp.cpp").write_text(plugin_source)
        plugin = work / "plugin.so"
        object_file = work / "source.o"
        args = [clang, "-c", "source.c", "-o", "source.o", *plugin_flags(plugin)]

        def compile_object(wrapper):
            object_file.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            artifact = object_file.read_bytes() if object_file.exists() else None
            return completed.returncode, completed.stdout, completed.stderr, artifact

        first_object = None
        for revision, stamp in enumerate([1, 2]):
            build = subprocess.run([str(llvm / "clang++"), "-shared", "-fPIC",
                                    f"-DSTAMP_VALUE={stamp}", *shlex.split(flags),
                                    "stamp.cpp", "-L" + str(llvm.parent / "lib"),
                                    "-lclang-cpp", "-Wl,-rpath," + str(llvm.parent / "lib"),
                                    "-o", "plugin.so"], cwd=work, env=env,
                                   capture_output=True, timeout=120)
            assert build.returncode == 0, (fixture, build.stderr)
            direct = compile_object([])
            assert (direct[0] == 0 and f"accache stamp {stamp}".encode()
                    in direct[2]), (fixture, direct[:3])
            if first_object is None:
                first_object = direct[3]
            else:
                assert direct[3] == first_object, "diagnostic plugin changed object bytes"

            if fixture == "clang-frontend-plugin":
                # Pinned sccache converts -fplugin=path to a separated form
                # that Clang rejects. Accache keeps the caller's original argv.
                for _ in range(2):
                    oracle = compile_object([sccache])
                    assert (oracle[0] != 0 and oracle[3] is None
                            and b"unknown argument: '-fplugin'" in oracle[2]), oracle[:3]
                oracle_hit = False
                oracle_exit_code = oracle[0]
            else:
                before_hits = hits()
                assert compile_object([sccache]) == direct
                assert hits() == before_hits, (fixture, "sccache ignored the plugin edit")
                before_hits = hits()
                assert compile_object([sccache]) == direct
                assert hits() > before_hits, (fixture, "sccache did not warm-hit")
                oracle_hit = True
                oracle_exit_code = 0

            assert compile_object([accache]) == direct
            cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            if revision:
                assert any("plugin.so" in item for item in cold["changes"]), cold
            assert compile_object([accache]) == direct
            warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)
            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": oracle_hit, "accache": "hit",
                            "oracle_exit_code": oracle_exit_code,
                            "artifacts": ["source.o"]})

        print("PASS oracle", fixture, "plugin diagnostic invalidation", flush=True)
    return results


def check_rust_llvm_plugin(root, env, accache, sccache, rustc, clang, hits):
    """Track an LLVM pass plugin omitted from rustc dep-info."""
    work = root / "rust-llvm-plugin"
    work.mkdir()
    (work / "target").mkdir()
    (work / "library.rs").write_text("pub fn answer() -> u32 { 42 }\n")
    plugin = work / "plugin.so"
    library = work / "target/libexample.rlib"
    depfile = work / "target/example.d"
    rust_env = env | {"RUSTC_BOOTSTRAP": "1"}
    args = [rustc, "--crate-name=example", "--crate-type=rlib",
            "--emit=link,dep-info", "--out-dir=target", "-Copt-level=2",
            "-Zllvm-plugins=" + str(plugin), "library.rs"]

    def compile_library(wrapper):
        library.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=rust_env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return (completed.stdout, completed.stderr,
                library.read_bytes(), depfile.read_bytes())

    results = []
    first_library = None
    for revision, stamp in enumerate([1, 2]):
        build_llvm_stamp_plugin(work, clang, env, stamp)
        direct = compile_library([])
        assert b"plugin.so" not in direct[3], "dep-info listed LLVM plugin"
        if first_library is None:
            first_library = direct[2]
        else:
            assert direct[2] != first_library, "LLVM plugin edit had no effect"

        before_hits = hits()
        oracle_cold = compile_library([sccache])
        oracle_hit = hits() > before_hits
        if oracle_cold != direct:
            assert (revision == 1 and oracle_hit
                    and oracle_cold[2] == first_library), "unexpected sccache difference"
        before_hits = hits()
        assert compile_library([sccache]) == oracle_cold
        assert hits() > before_hits, "sccache did not warm-hit"

        assert compile_library([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
        assert cold["outcome"] == "miss", (revision, cold)
        if revision:
            assert any("plugin.so" in item for item in cold["changes"]), cold
        assert compile_library([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
        assert warm["outcome"] == "hit", (revision, warm)
        results.append({"fixture": "rust-llvm-plugin", "revision": revision,
                        "oracle_hit": True, "oracle_stale_artifact": oracle_cold != direct,
                        "accache": "hit",
                        "artifacts": ["target/libexample.rlib", "target/example.d"]})

    print("PASS oracle rust-llvm-plugin input invalidation", flush=True)
    return results


def check_clang_llvm_file_inputs(root, env, accache, sccache, clang, hits):
    """Hash files read through Clang's LLVM option forwarding."""
    results = []
    for fixture, forwarded in [
        ("clang-llvm-attrs-separated", ["-mllvm", "-forceattrs-csv-path=attrs.csv"]),
        ("clang-llvm-attrs-joined", ["-mllvm=-forceattrs-csv-path=attrs.csv"]),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "source.c").write_text(
            "int answer(int x) { return x > 100 ? x * 3 : x + 2; }\n")
        attrs = work / "attrs.csv"
        object_file = work / "source.o"
        depfile = work / "source.d"
        args = [clang, "-O2", "-c", "source.c", "-o", "source.o",
                "-MD", "-MF", "source.d", *forwarded]

        def compile_object(wrapper):
            object_file.unlink(missing_ok=True)
            depfile.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return (completed.stdout, completed.stderr,
                    object_file.read_bytes(), depfile.read_bytes())

        first_object = None
        for revision, contents in enumerate(["answer,noinline\n", "answer,optnone\n"]):
            attrs.write_text(contents)
            direct = compile_object([])
            assert b"attrs.csv" not in direct[3], (fixture, "LLVM input in depfile")
            if first_object is None:
                first_object = direct[2]
            else:
                assert direct[2] != first_object, (fixture, "LLVM file edit had no effect")

            oracle_cold = compile_object([sccache])
            before_hits = hits()
            assert compile_object([sccache]) == oracle_cold
            oracle_hit = hits() > before_hits
            assert oracle_hit or oracle_cold == direct, (fixture, revision, oracle_cold)

            assert compile_object([accache]) == direct
            cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            if revision:
                assert any("attrs.csv" in item for item in cold["changes"]), cold
            assert compile_object([accache]) == direct
            warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)

            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": oracle_hit,
                            "oracle_stale_artifact": oracle_cold[2] != direct[2],
                            "accache": "hit",
                            "artifacts": ["source.o", "source.d"]})

        print("PASS oracle", fixture, "LLVM file invalidation", flush=True)
    return results


def check_clang_llvm_report_passthrough(root, env, accache, sccache, clang, hits):
    """Preserve both known dump files and less familiar live LLVM reports."""
    results = []
    for fixture, forwarded, report_file in [
        ("clang-llvm-ir-dump",
         ["-mllvm", "-print-after=instcombine",
          "-mllvm", "-ir-dump-directory=dumps"], True),
        ("clang-llvm-unknown-report",
         ["-mllvm=-debug-pass=Structure"], False),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "dumps").mkdir()
        (work / "source.c").write_text("int answer(int x) { return x + 1; }\n")
        object_file = work / "source.o"
        args = [clang, "-O2", "-c", "source.c", "-o", "source.o", *forwarded]

        def compile_object(wrapper):
            object_file.unlink(missing_ok=True)
            for path in (work / "dumps").iterdir():
                path.unlink()
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            reports = {path.name: path.read_bytes()
                       for path in (work / "dumps").iterdir()}
            return (completed.stdout, completed.stderr, object_file.read_bytes(), reports)

        direct = compile_object([])
        if report_file:
            assert direct[3], (fixture, "LLVM wrote no dump files")
        else:
            assert b"Pass Arguments:" in direct[1], (fixture, "LLVM wrote no report")

        oracle_cold = compile_object([sccache])
        before_hits = hits()
        oracle_warm = compile_object([sccache])
        oracle_hit = hits() > before_hits
        assert oracle_cold[2] == direct[2] and oracle_warm[2] == direct[2]

        for _ in range(2):
            assert compile_object([accache]) == direct, fixture
            event = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert event["outcome"] == "bypass", (fixture, event)
            reason = ("invocation report" if report_file else "no audited cache contract")
            assert reason in event["reason"], (fixture, event)

        results.append({"fixture": fixture, "revision": 0,
                        "oracle_hit": oracle_hit, "accache": "bypass",
                        "oracle_missing_artifacts": sorted(set(direct[3]) - set(oracle_warm[3])),
                        "artifacts": ["source.o", *sorted("dumps/" + name for name in direct[3])]})
        print("PASS oracle", fixture, "passthrough", flush=True)
    return results


def check_rust_codegen_backend(root, env, accache, sccache, rustc, hits):
    """Cache the built-in backend and pass through undeclared runtime libraries."""
    results = []
    rust_env = env | {"RUSTC_BOOTSTRAP": "1"}
    undeclared_manifest = json.loads(Path(env["ACCACHE_MANIFEST"]).read_text())
    undeclared_manifest["read_roots"] = []
    undeclared_manifest_path = root / "manifest-without-read-roots.json"
    undeclared_manifest_path.write_text(json.dumps(undeclared_manifest))
    undeclared_env = rust_env | {"ACCACHE_MANIFEST": str(undeclared_manifest_path)}
    for fixture, backend_flags in [
        ("rust-codegen-backend-llvm", ["-Zcodegen-backend=llvm"]),
        ("rust-codegen-backend-last-llvm",
         ["-Zcodegen-backend=backend.so", "-Zcodegen-backend=llvm"]),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "target").mkdir()
        (work / "backend.so").write_bytes(b"not a dynamic library")
        source = work / "source.rs"
        library = work / "target/libexample.rlib"
        depfile = work / "target/example.d"
        args = [rustc, "--crate-name=example", "--crate-type=rlib",
                "--emit=link,dep-info", "--out-dir=target", *backend_flags,
                "source.rs"]

        def compile_library(wrapper):
            library.unlink(missing_ok=True)
            depfile.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=rust_env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return (completed.stdout, completed.stderr,
                    library.read_bytes(), depfile.read_bytes())

        first_library = None
        for revision, value in enumerate([42, 73]):
            source.write_text(f"pub fn answer() -> u32 {{ {value} }}\n")
            direct = compile_library([])
            if first_library is None:
                first_library = direct[2]
            else:
                assert direct[2] != first_library, (fixture, "source edit had no effect")

            assert compile_library([sccache])[2:] == direct[2:]
            before_hits = hits()
            assert compile_library([sccache])[2:] == direct[2:]
            oracle_hit = hits() > before_hits

            assert compile_library([accache]) == direct, (fixture, revision, "cold")
            cold = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            assert compile_library([accache]) == direct, (fixture, revision, "warm")
            warm = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)

            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": oracle_hit, "accache": "hit",
                            "artifacts": ["target/libexample.rlib", "target/example.d"]})

        print("PASS oracle", fixture, "backend selection", flush=True)

    for fixture, backend_flags, error_text in [
        ("rust-codegen-backend-path-joined", ["-Zcodegen-backend=backend.so"],
         b"couldn't load codegen backend"),
        ("rust-codegen-backend-path-separated", ["-Z", "codegen-backend=backend.so"],
         b"couldn't load codegen backend"),
        ("rust-codegen-backend-name", ["-Zcodegen-backend=unknown"],
         b"failed to find a `codegen-backends` folder"),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "target").mkdir()
        (work / "backend.so").write_bytes(b"not a dynamic library")
        (work / "source.rs").write_text("pub fn answer() -> u32 { 42 }\n")
        args = [rustc, "--crate-name=example", "--crate-type=rlib",
                "--emit=link,dep-info", "--out-dir=target", *backend_flags,
                "source.rs"]

        def invoke(wrapper, invocation_env):
            completed = subprocess.run([*wrapper, *args], cwd=work, env=invocation_env,
                                       capture_output=True, timeout=120)
            return completed.returncode, completed.stdout, completed.stderr

        direct = invoke([], rust_env)
        assert direct[0] != 0 and error_text in direct[2], direct
        oracle = invoke([sccache], rust_env)
        assert oracle[0] == direct[0], (fixture, oracle)
        for _ in range(2):
            assert invoke([accache], undeclared_env) == direct, fixture
            event = json.loads(subprocess.check_output([accache, "explain"], env=undeclared_env))
            assert (event["outcome"] == "bypass"
                    and "compiler extension requires manifest read_roots" in event["reason"]), event

        assert invoke([accache], rust_env) == direct, fixture
        event = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
        assert (event["outcome"] == "bypass"
                and "rustc output discovery failed" in event["reason"]), event

        results.append({"fixture": fixture, "revision": 0,
                        "oracle_hit": False, "accache": "bypass",
                        "artifacts": []})
        print("PASS oracle", fixture, "undeclared backend passthrough", flush=True)

    return results


def check_rust_replayable_reports(root, env, accache, sccache, rustc, hits):
    """Replay deterministic compiler reports with their matching library."""
    cases = [
        ("print-codegen-stats", b"===", "stdout"),
        ("print-llvm-passes", b"Pass Arguments:", "stderr"),
        ("print-mono-items", b"MONO_ITEM", "stdout"),
        ("print-type-sizes", b"print-type-size", "stdout"),
        ("input-stats", b"ast-stats", "stderr"),
        ("macro-stats", b"macro-stats", "stderr"),
        ("meta-stats", b"meta-stats", "stderr"),
    ]
    results = []
    rust_env = env | {"RUSTC_BOOTSTRAP": "1"}
    for name, marker, stream in cases:
        fixture = "rust-" + name
        work = root / fixture
        work.mkdir()
        (work / "target").mkdir()
        source = work / "library.rs"
        args = [rustc, "--crate-name=example", "--crate-type=rlib",
                "--emit=link,dep-info", "--out-dir=target", "library.rs", "-Z" + name]

        def compile_library(wrapper):
            (work / "target/libexample.rlib").unlink(missing_ok=True)
            (work / "target/example.d").unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=rust_env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return (completed.stdout, completed.stderr,
                    (work / "target/libexample.rlib").read_bytes(),
                    (work / "target/example.d").read_bytes())

        first_library = None
        for revision, value in enumerate([42, 73]):
            source.write_text(
                "pub struct Pair { pub left: u32, pub right: u32 }\n"
                f"pub fn answer() -> u32 {{ Pair {{ left: 2, right: {value} }}.right }}\n")
            direct = compile_library([])
            report = direct[0] if stream == "stdout" else direct[1]
            assert marker in report, (fixture, revision, report)
            if first_library is None:
                first_library = direct[2]
            else:
                assert direct[2] != first_library, (fixture, "source edit had no effect")

            assert compile_library([sccache]) == direct, (fixture, revision, "oracle cold")
            before_hits = hits()
            assert compile_library([sccache]) == direct, (fixture, revision, "oracle warm")
            assert hits() > before_hits, (fixture, revision, "oracle did not hit")

            assert compile_library([accache]) == direct, (fixture, revision, "cold")
            cold = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            assert compile_library([accache]) == direct, (fixture, revision, "warm")
            warm = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)

            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": True, "accache": "hit",
                            "artifacts": ["target/libexample.rlib", "target/example.d"]})

        print("PASS oracle", fixture, "report replay", flush=True)

    return results


def check_rust_shell_argfiles(root, env, accache, sccache, rustc, hits):
    """Cache quoted Rust argfiles and invalidate after an option edit."""
    results = []
    rust_env = env | {"RUSTC_BOOTSTRAP": "1"}
    for fixture, unstable in [
        ("rust-shell-argfile-joined", ["-Zshell-argfiles"]),
        ("rust-shell-argfile-separated", ["-Z", "shell-argfiles"]),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "target files").mkdir()
        (work / "source.rs").write_text(
            "pub fn answer(x: u32) -> u32 { if x > 100 { x * 3 } else { x + 2 } }\n")
        response = work / "args.rsp"
        library = work / "target files/libexample.rlib"
        depfile = work / "target files/example.d"
        args = [rustc, *unstable, "@shell:args.rsp"]

        def compile_library(wrapper):
            library.unlink(missing_ok=True)
            depfile.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=rust_env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return (completed.stdout, completed.stderr,
                    library.read_bytes(), depfile.read_bytes())

        first_library = None
        for revision, optimization in enumerate([0, 2]):
            response.write_text(
                '--crate-name example --crate-type rlib --emit link,dep-info '
                f'--out-dir "target files" -Copt-level={optimization} source.rs\n')
            direct = compile_library([])
            if first_library is None:
                first_library = direct[2]
            else:
                assert direct[2] != first_library, (fixture, "argfile edit had no effect")

            oracle_cold = compile_library([sccache])
            before_hits = hits()
            oracle_warm = compile_library([sccache])
            oracle_hit = hits() > before_hits
            assert oracle_cold[2:] == oracle_warm[2:], (fixture, revision)
            if not oracle_hit:
                assert oracle_cold[2:] == direct[2:], (fixture, revision)

            assert compile_library([accache]) == direct, (fixture, revision, "cold")
            cold = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            if revision:
                assert any("args.rsp" in item for item in cold["changes"]), cold
            assert compile_library([accache]) == direct, (fixture, revision, "warm")
            warm = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)

            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": oracle_hit,
                            "oracle_stale_artifact": oracle_cold[2] != direct[2],
                            "accache": "hit",
                            "artifacts": ["target files/libexample.rlib",
                                          "target files/example.d"]})

        print("PASS oracle", fixture, "shell argfile invalidation", flush=True)
    return results


def check_rust_shell_literal_at_passthrough(root, env, accache, sccache, rustc):
    """Keep an @-prefixed source from a shell argfile literal."""
    work = root / "rust-shell-literal-at"
    work.mkdir()
    (work / "target").mkdir()
    (work / "@source.rs").write_text("pub fn answer() -> u32 { 42 }\n")
    (work / "args.rsp").write_text(
        "--crate-name example --crate-type rlib --emit link,dep-info "
        "--out-dir target '@source.rs'\n")
    library = work / "target/libexample.rlib"
    depfile = work / "target/example.d"
    rust_env = env | {"RUSTC_BOOTSTRAP": "1"}
    args = [rustc, "-Zshell-argfiles", "@shell:args.rsp"]

    def compile_library(wrapper):
        library.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=rust_env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return (completed.stdout, completed.stderr,
                library.read_bytes(), depfile.read_bytes())

    direct = compile_library([])
    assert compile_library([sccache])[2:] == direct[2:]
    for _ in range(2):
        assert compile_library([accache]) == direct
        event = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
        assert (event["outcome"] == "bypass"
                and "literal @ argument" in event["reason"]), event

    print("PASS oracle rust-shell-literal-at passthrough", flush=True)
    return {"fixture": "rust-shell-literal-at", "revision": 0,
            "accache": "bypass", "artifacts": ["target/libexample.rlib",
                                                "target/example.d"]}


def check_rust_llvm_file_inputs(root, env, accache, sccache, rustc, hits):
    """Track LLVM section and function-attribute files omitted from dep-info."""
    results = []
    for fixture, llvm_option, input_name, revisions, opt_level, separated in [
        ("rust-llvm-list-joined", "--basic-block-sections=functions.txt",
         "functions.txt", ["!answer\n!!1\n", "!other\n!!1\n"], 0, False),
        ("rust-llvm-list-separated", "--basic-block-sections=functions.txt",
         "functions.txt", ["!answer\n!!1\n", "!other\n!!1\n"], 0, True),
        ("rust-llvm-attrs-joined", "--forceattrs-csv-path=attrs.csv",
         "attrs.csv", ["answer,noinline\n", "answer,optnone\n"], 2, False),
        ("rust-llvm-attrs-separated", "--forceattrs-csv-path=attrs.csv",
         "attrs.csv", ["answer,noinline\n", "answer,optnone\n"], 2, True),
    ]:
        work = root / fixture
        work.mkdir()
        (work / "target").mkdir()
        (work / "source.rs").write_text(
            '#[no_mangle] pub extern "C" fn answer(x: i32) -> i32 {\n'
            '    if x > 100 { x * 3 } else { x + 2 }\n'
            '}\n'
            '#[no_mangle] pub extern "C" fn other(x: i32) -> i32 {\n'
            '    if x < 0 { x * 5 } else { x - 7 }\n'
            '}\n')
        input_file = work / input_name
        library = work / "target/libexample.rlib"
        depfile = work / "target/example.d"
        codegen = (["-C", "llvm-args=" + llvm_option] if separated
                   else ["-Cllvm-args=" + llvm_option])
        args = [rustc, "--crate-name=example", "--crate-type=rlib",
                "--emit=link,dep-info", "--out-dir=target",
                "-Copt-level=" + str(opt_level),
                *codegen, "source.rs"]

        def compile_library(wrapper):
            library.unlink(missing_ok=True)
            depfile.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (fixture, wrapper, completed.stderr)
            return (completed.stdout, completed.stderr,
                    library.read_bytes(), depfile.read_bytes())

        first_library = None
        for revision, contents in enumerate(revisions):
            input_file.write_text(contents)
            direct = compile_library([])
            assert input_name.encode() not in direct[3], (
                fixture, "LLVM input appeared in dep-info")
            if first_library is None:
                first_library = direct[2]
            else:
                assert direct[2] != first_library, (fixture, "LLVM file edit had no effect")

            before_hits = hits()
            oracle_cold = compile_library([sccache])
            oracle_hit = hits() > before_hits
            if oracle_cold != direct:
                assert (revision == 1 and oracle_hit
                        and oracle_cold[2] == first_library), (
                            fixture, revision, "unexpected sccache difference")
            before_hits = hits()
            assert compile_library([sccache]) == oracle_cold
            assert hits() > before_hits, (fixture, "sccache did not warm-hit")

            assert compile_library([accache]) == direct
            cold = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert cold["outcome"] == "miss", (fixture, revision, cold)
            if revision:
                assert any(input_name in item for item in cold["changes"]), cold
            assert compile_library([accache]) == direct
            warm = json.loads(subprocess.check_output([accache, "explain"], env=env))
            assert warm["outcome"] == "hit", (fixture, revision, warm)
            results.append({"fixture": fixture, "revision": revision,
                            "oracle_hit": True,
                            "oracle_stale_artifact": oracle_cold != direct,
                            "accache": "hit",
                            "artifacts": ["target/libexample.rlib", "target/example.d"]})

        print("PASS oracle", fixture, "LLVM file invalidation", flush=True)
    return results


def check_rust_llvm_report_passthrough(root, env, accache, sccache, rustc, hits):
    """Keep LLVM pass dumps live rather than replaying only the rlib."""
    work = root / "rust-llvm-ir-dump"
    work.mkdir()
    (work / "target").mkdir()
    (work / "dumps").mkdir()
    (work / "source.rs").write_text(
        '#[no_mangle] pub extern "C" fn answer(x: i32) -> i32 {\n'
        '    if x > 0 { x * 3 } else { x + 7 }\n'
        '}\n')
    args = [rustc, "--crate-name=example", "--crate-type=rlib",
            "--emit=link,dep-info", "--out-dir=target", "-Copt-level=2",
            "-Cllvm-args=--print-after=instcombine --ir-dump-directory=dumps",
            "source.rs"]

    def compile_library(wrapper):
        for name in ["target/libexample.rlib", "target/example.d"]:
            (work / name).unlink(missing_ok=True)
        for path in (work / "dumps").iterdir():
            path.unlink()
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        artifacts = {name: value for name, value in snapshot(work).items()
                     if name != "source.rs"}
        return completed, artifacts

    direct, expected = compile_library([])
    dump_files = {name for name in expected if name.startswith("dumps/")}
    assert direct.returncode == 0 and len(dump_files) >= 5, (
        direct.returncode, direct.stderr, sorted(expected))
    assert {"target/libexample.rlib", "target/example.d"} <= set(expected)

    oracle_snapshots = []
    for _ in range(2):
        before_hits = hits()
        oracle, artifacts = compile_library([sccache])
        assert oracle.returncode == 0, (oracle.returncode, oracle.stderr)
        assert artifacts["target/libexample.rlib"] == expected["target/libexample.rlib"]
        oracle_snapshots.append((artifacts, hits() > before_hits))

    for attempt in range(2):
        actual, artifacts = compile_library([accache])
        assert (actual.returncode, actual.stdout, actual.stderr, artifacts) == (
            direct.returncode, direct.stdout, direct.stderr, expected), (
                attempt, actual.returncode, actual.stderr,
                sorted(artifacts), sorted(expected))
        event = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert (event["outcome"] == "bypass"
                and "invocation report" in event["reason"]), event

    oracle_missing = sorted(dump_files - set(oracle_snapshots[-1][0]))
    print("PASS oracle rust-llvm-ir-dump passthrough", flush=True)
    return {"fixture": "rust-llvm-ir-dump", "revision": 0,
            "oracle_hit": oracle_snapshots[-1][1], "accache": "bypass",
            "oracle_missing_artifacts": oracle_missing,
            "artifacts": sorted(expected)}


def check_rust_llvm_unknown_passthrough(root, env, accache, sccache, rustc, hits):
    """Preserve a live LLVM pass report without an audited cache contract."""
    work = root / "rust-llvm-unknown-report"
    work.mkdir()
    (work / "target").mkdir()
    (work / "source.rs").write_text("pub fn answer(x: u32) -> u32 { x + 1 }\n")
    library = work / "target/libexample.rlib"
    depfile = work / "target/example.d"
    args = [rustc, "--crate-name=example", "--crate-type=rlib",
            "--emit=link,dep-info", "--out-dir=target", "-Copt-level=2",
            "-Cllvm-args=--debug-pass=Structure", "source.rs"]

    def compile_library(wrapper):
        library.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return (completed.stdout, completed.stderr,
                library.read_bytes(), depfile.read_bytes())

    direct = compile_library([])
    assert b"Pass Arguments:" in direct[1], "LLVM emitted no live pass report"
    assert compile_library([sccache])[2:] == direct[2:]
    before_hits = hits()
    assert compile_library([sccache])[2:] == direct[2:]
    oracle_hit = hits() > before_hits

    for attempt in range(2):
        assert compile_library([accache]) == direct, (
            attempt, "accache changed a direct LLVM report")
        event = json.loads(subprocess.check_output([accache, "explain"], env=env))
        assert (event["outcome"] == "bypass"
                and "no audited cache contract" in event["reason"]), event

    print("PASS oracle rust-llvm-unknown-report passthrough", flush=True)
    return {"fixture": "rust-llvm-unknown-report", "revision": 0,
            "oracle_hit": oracle_hit, "accache": "bypass",
            "artifacts": ["target/libexample.rlib", "target/example.d"]}


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


def check_rust_sample_profile_use(root, env, accache, sccache, rustc, hits):
    """Hash the contents of Rust's unstable sample profile input."""
    results = []
    rust_env = env | {"RUSTC_BOOTSTRAP": "1"}
    for spelling, flag in [
        ("joined", ["-Zprofile-sample-use=sample.prof"]),
        ("separated", ["-Z", "profile-sample-use=sample.prof"]),
    ]:
        name = "rust-sample-profile-use-" + spelling
        work = root / name
        work.mkdir()
        (work / "target").mkdir()
        (work / "library.rs").write_text("pub fn answer() -> u32 { 42 }\n")
        profile = work / "sample.prof"
        args = [rustc, "--crate-name=example", "--crate-type=rlib",
                "--emit=link,dep-info", "--out-dir=target", "library.rs",
                "-Cmetadata=" + name, *flag]

        def compile_library(wrapper):
            for path in [work / "target/libexample.rlib", work / "target/example.d"]:
                path.unlink(missing_ok=True)
            completed = subprocess.run([*wrapper, *args], cwd=work, env=rust_env,
                                       capture_output=True, timeout=120)
            assert completed.returncode == 0, (name, wrapper, completed.stderr)
            return (completed.stdout, completed.stderr,
                    (work / "target/libexample.rlib").read_bytes(),
                    (work / "target/example.d").read_bytes())

        for revision, samples in enumerate([100, 200]):
            profile.write_text(f"foo:{samples}:0\n 1: {samples}\n")
            direct = compile_library([])

            before_cold_hits = hits()
            assert compile_library([sccache]) == direct, (name, revision)
            assert hits() == before_cold_hits, (
                name, revision, "sccache ignored the changed sample profile")
            before_hits = hits()
            assert compile_library([sccache]) == direct, (name, revision)
            assert hits() > before_hits, (name, revision, "sccache did not hit")

            assert compile_library([accache]) == direct, (name, revision, "cold")
            cold = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert cold["outcome"] == "miss", (name, revision, cold)
            if revision:
                assert any("sample.prof" in item for item in cold["changes"]), cold
            assert compile_library([accache]) == direct, (name, revision, "warm")
            warm = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
            assert warm["outcome"] == "hit", (name, revision, warm)

            results.append({"fixture": name, "revision": revision,
                            "oracle_hit": True, "accache": "hit",
                            "oracle_profile_input_tracked": True,
                            "artifacts": ["target/example.d", "target/libexample.rlib"]})

        print("PASS oracle", name, "profile invalidation", flush=True)

    return results


def check_rust_sanitizer_abilist(root, env, accache, sccache, rustc, hits):
    """Invalidate a Rust dataflow sanitizer ABI list omitted from dep-info."""
    work = root / "rust-sanitizer-abilist"
    work.mkdir()
    (work / "target").mkdir()
    (work / "library.rs").write_text(
        '#[no_mangle] pub extern "C" fn answer(x: u32) -> u32 { x + 42 }\n')
    abilist = work / "abi.txt"
    rust_env = env | {"RUSTC_BOOTSTRAP": "1"}
    args = [rustc, "--crate-name=example", "--crate-type=rlib",
            "--emit=link,dep-info", "--out-dir=target", "library.rs",
            "-Zsanitizer=dataflow", "-Zsanitizer-dataflow-abilist=abi.txt",
            "-Cunsafe-allow-abi-mismatch=sanitizer"]

    def compile_library(wrapper):
        output = work / "target/libexample.rlib"
        depfile = work / "target/example.d"
        output.unlink(missing_ok=True)
        depfile.unlink(missing_ok=True)
        completed = subprocess.run([*wrapper, *args], cwd=work, env=rust_env,
                                   capture_output=True, timeout=120)
        assert completed.returncode == 0, (wrapper, completed.stderr)
        return (completed.stdout, completed.stderr,
                output.read_bytes(), depfile.read_bytes())

    results = []
    previous = None
    for revision, contents in enumerate(["fun:answer=uninstrumented\n", ""]):
        abilist.write_text(contents)
        direct = compile_library([])
        assert b"abi.txt" not in direct[3], "rustc started tracking ABI lists in dep-info"
        if previous is not None:
            assert direct[2] != previous[2], "ABI list did not change the object"

        before_hits = hits()
        oracle = compile_library([sccache])
        if revision == 0:
            assert oracle == direct, "sccache cold result differs"
            assert hits() == before_hits, "sccache had an unexpected ABI-list hit"
            before_hits = hits()
            assert compile_library([sccache]) == direct
            assert hits() > before_hits, "sccache did not hit the ABI-list action"
        else:
            assert hits() > before_hits, "sccache unexpectedly invalidated the ABI list"
            assert oracle[2] == previous[2] and oracle[2] != direct[2], (
                "sccache did not replay the stale object", oracle[2], direct[2])

        assert compile_library([accache]) == direct
        cold = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
        assert cold["outcome"] == "miss", cold
        if revision:
            assert any("abi.txt" in item for item in cold["changes"]), cold
        assert compile_library([accache]) == direct
        warm = json.loads(subprocess.check_output([accache, "explain"], env=rust_env))
        assert warm["outcome"] == "hit", warm

        results.append({"fixture": "rust-sanitizer-abilist", "revision": revision,
                        "oracle_hit": True, "accache": "hit",
                        "oracle_stale_artifact": revision == 1,
                        "artifacts": ["target/example.d", "target/libexample.rlib"]})
        previous = direct

    print("PASS oracle Rust sanitizer ABI-list invalidation", flush=True)
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

            def nondeterministic(path):
                return any(fnmatch.fnmatchcase(path, pattern)
                           for pattern in fixture.nondeterministic_outputs)

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
                    "gcc-aux-info": {"source.aux"},
                    "gcc-aux-info-joined": {"source.aux"},
                    "gcc-explicit-tree-dump": {"report.txt"},
                    "gcc-go-spec": {"spec.go"},
                    "gcc-optimization-record": {"source.c.opt-record.json.gz"},
                    "gcc-final-insns-default": {"source.c.gkd"},
                    "gcc-final-insns-dot": {"source.c.gkd"},
                    "gcc-final-insns-explicit": {"final.gkd"},
                    "gcc-opt-report": {"report.txt"},
                    "gcc-sarif-report": {"source.c.sarif"},
                    "gcc-sarif-nested-output": {"objects/source.c.c.sarif"},
                    "gcc-add-sarif-output": {"added.sarif"},
                    "gcc-add-default-sarif": {"source.c.sarif"},
                    "gcc-set-sarif-output": {"set.sarif"},
                    "gcc-sarif-output-parameters": {"parameters.sarif"},
                    "gcc-multiple-sarif-outputs": {"added.sarif", "set.sarif"},
                    "gcc-sarif-then-text": {"source.c.sarif"},
                    "gcc-html-output": {"source.c.html"},
                    "gcc-html-output-options": {"report.html"},
                    "gcc-html-cfgs": {"cfgs.html"},
                    "gcc-html-state-diagrams": {"state.html"},
                    "gcc-html-graph-details": {"details.html"},
                    "clang-serialized-diagnostics": {"source.dia"},
                    "gcc-wa-depfile": {"asm.d"},
                    "gcc-wa-mixed-depfile": {"asm.d"},
                    "gcc-xassembler-depfile": {"asm.d"},
                    "gcc-wa-listing": {"listing.lst"},
                    "gcc-xassembler-listing": {"listing.lst"},
                    "gcc-wa-listing-and-depfile": {"asm.d", "listing.lst"},
                    "clang-external-assembler-depfile": {"asm.d"},
                    "clang-external-assembler-listing": {"listing.lst"},
                }
                if (side_files := missing_oracle_side_files.get(fixture.name)) and label == "sccache warm vs direct":
                    # These accepted flags produce files that pinned sccache
                    # omits from its action result. Accache must restore them.
                    assert side_files.issubset(expected[3])
                    expected = (*expected[:3], {key: value for key, value in expected[3].items()
                                               if key not in side_files})
                    assert side_files.isdisjoint(actual[3]), (
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
                                    "gcc-tree-all-dumps", "gcc-statistics-dump",
                                    "gcc-debug-dumps", "gcc-joined-debug-dumps",
                                    "gcc-analyzer-text", "gcc-analyzer-exploded-graph",
                                    "gcc-analyzer-exploded-nodes-2",
                                    "gcc-analyzer-exploded-nodes-3",
                                    "gcc-analyzer-exploded-paths",
                                    "gcc-analyzer-feasibility",
                                    "gcc-analyzer-infinite-loop",
                                    "gcc-analyzer-state-purge", "gcc-analyzer-supergraph",
                                    "gcc-analyzer-json", "gcc-debug-dump",
                                    "gcc-earlydebug-dump"} and label == "sccache warm vs direct":
                    dump_files = {path for path in expected[3]
                                  if path.startswith("source.c.")}
                    expected_count = {"gcc-tree-dump": 1, "gcc-multiple-dumps": 2,
                                      "gcc-statistics-dump": 1,
                                      "gcc-analyzer-text": 1,
                                      "gcc-analyzer-exploded-graph": 1,
                                      "gcc-analyzer-exploded-nodes-2": 1,
                                      "gcc-analyzer-exploded-paths": 1,
                                      "gcc-analyzer-feasibility": 3,
                                      "gcc-analyzer-infinite-loop": 1,
                                      "gcc-analyzer-state-purge": 1,
                                      "gcc-analyzer-json": 1,
                                      "gcc-debug-dump": 1,
                                      "gcc-earlydebug-dump": 1}
                    if fixture.name in {"gcc-tree-all-dumps", "gcc-debug-dumps",
                                        "gcc-joined-debug-dumps", "gcc-analyzer-supergraph",
                                        "gcc-analyzer-exploded-nodes-3"}:
                        minimum = (100 if fixture.name == "gcc-tree-all-dumps" else
                                   5 if fixture.name.startswith("gcc-analyzer-") else 60)
                        assert len(dump_files) >= minimum, ("unexpected GCC dump files", expected[3])
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
                    if (fixture.name == "gcc-dump-internal-locations"
                            and field == "stderr" and label.startswith("sccache ")):
                        # sccache compiles preprocessed source, whose stripped
                        # macro whitespace changes this location-map dump.
                        # Accache must still match direct GCC byte for byte.
                        assert b"ORDINARY MAP" in left and b"ORDINARY MAP" in right
                        continue
                    if field == "artifacts" and fixture.nondeterministic_outputs:
                        # GCC PCH embeds process-specific state even when direct
                        # compilations receive identical argv and inputs.
                        left = {path: (b"", mode) if nondeterministic(path)
                                else (data, mode) for path, (data, mode) in left.items()}
                        right = {path: (b"", mode) if nondeterministic(path)
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
                if fixture.name == "gcc-go-spec":
                    assert direct[3]["spec.go"][0], "GCC Go specification is empty"
                if fixture.name == "gcc-optimization-record":
                    assert direct[3]["source.c.opt-record.json.gz"][0], (
                        "GCC optimization record is empty")
                if fixture.name.startswith("gcc-final-insns-"):
                    report = ("final.gkd" if fixture.name.endswith("explicit") else
                              "source.c.gkd")
                    assert direct[3][report][0], "GCC final instruction dump is empty"
                if fixture.name.startswith("gcc-html-") and fixture.name not in {
                        "gcc-html-output", "gcc-html-output-options"}:
                    report = {"gcc-html-cfgs": "cfgs.html",
                              "gcc-html-state-diagrams": "state.html",
                              "gcc-html-graph-details": "details.html"}[fixture.name]
                    assert b"<svg" in direct[3][report][0], (
                        fixture.name, "AOS Graphviz did not render embedded SVG")
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
                    for path in oracle_warm[3]:
                        if nondeterministic(path):
                            assert oracle_warm[3][path] == oracle_cold[3][path], (
                                fixture.name, "sccache did not replay the cold artifact")
                oracle_hit = hits() > before_hits
                if fixture.name in {"gcc-tree-dump", "gcc-multiple-dumps",
                                    "gcc-tree-all-dumps", "gcc-statistics-dump",
                                    "gcc-debug-dumps", "gcc-joined-debug-dumps",
                                    "gcc-analyzer-text", "gcc-analyzer-exploded-graph",
                                    "gcc-analyzer-exploded-nodes-2",
                                    "gcc-analyzer-exploded-nodes-3",
                                    "gcc-analyzer-exploded-paths",
                                    "gcc-analyzer-feasibility",
                                    "gcc-analyzer-infinite-loop",
                                    "gcc-analyzer-state-purge", "gcc-analyzer-supergraph",
                                    "gcc-analyzer-json", "gcc-debug-dump",
                                    "gcc-earlydebug-dump",
                                    "gcc-go-spec",
                                    "gcc-optimization-record",
                                    "gcc-final-insns-default", "gcc-final-insns-dot",
                                    "gcc-final-insns-explicit",
                                    "gcc-explicit-tree-dump",
                                    "gcc-opt-report", "gcc-sarif-report",
                                    "gcc-sarif-nested-output", "gcc-add-sarif-output",
                                    "gcc-add-default-sarif", "gcc-set-sarif-output",
                                    "gcc-sarif-output-parameters", "gcc-multiple-sarif-outputs",
                                    "gcc-sarif-then-text", "gcc-html-output",
                                    "gcc-html-output-options", "gcc-html-cfgs",
                                    "gcc-html-state-diagrams", "gcc-html-graph-details"}:
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
                    for path in accache_warm[3]:
                        if nondeterministic(path):
                            assert accache_warm[3][path] == accache_cold[3][path], (
                                fixture.name, "accache did not replay the cold artifact")
                warm_event = json.loads(subprocess.check_output([accache, "explain"], env=env))
                if fixture.cacheable:
                    assert cold_event["outcome"] == "miss", (fixture.name, cold_event)
                    assert warm_event["outcome"] == "hit", (fixture.name, warm_event)
                    # An oracle that never caches is not a useful hit comparator.
                    assert oracle_hit, (fixture.name, "sccache did not hit", stats())
                else:
                    assert warm_event["outcome"] != "hit", (fixture.name, warm_event)
                    if fixture.name.startswith("rust-named-"):
                        # The pinned parser checks for a literal link or
                        # metadata emission before rejecting named emit kinds.
                        reason = ("not a cacheable compilation" if fixture.name == "rust-named-link"
                                  else "unsupported --emit")
                        assert (warm_event["outcome"] == "bypass"
                                and reason in warm_event["reason"]), (
                            fixture.name, warm_event)
                    if fixture.name == "clang-wp-mixed-md":
                        assert (warm_event["outcome"] == "bypass"
                                and "Clang mixed -Wp dependency output" in warm_event["reason"]), (
                            fixture.name, warm_event)
                results.append({"fixture": fixture.name, "revision": revision,
                                "oracle_hit": oracle_hit, "accache": warm_event["outcome"],
                                "oracle_missing_artifacts": sorted(set(baseline[3]) - set(oracle_warm[3])),
                                "artifacts": sorted(baseline[3])})
            print("PASS oracle", fixture.name, flush=True)

        results.extend(check_clang_driver_dependency_file(root, env, accache,
                                                          sccache, clang))
        results.extend(check_clang_cc1_dependency_file(root, env, accache,
                                                       sccache, clang, hits))
        results.extend(check_assembler_general_listing_passthrough(root, env,
                                                                   accache, sccache, gcc, hits))
        results.extend(check_rust_diagnostic_passthrough(root, env,
                                                         accache, sccache, rustc, hits))
        results.extend(check_rust_staged_compilation_passthrough(
            root, env, accache, sccache, rustc))
        results.extend(check_rust_no_codegen(root, env, accache, sccache,
                                             rustc, hits))
        results.extend(check_custom_dump_passthrough(root, env, accache, sccache, gcc, hits))
        results.extend(check_ada_specs(root, env, accache, sccache, gcc, hits))
        results.extend(check_gcc_joined_depfile(root, env, accache,
                                                sccache, gcc, hits))
        results.extend(check_c_timing_passthrough(root, env, accache,
                                                  sccache, gcc, clang, hits))
        results.append(check_gcc_analyzer_stderr_passthrough(root, env,
                                                             accache, sccache, gcc, hits))
        results.append(check_saved_temporaries(root, env, accache, sccache, rustc, hits))
        results.append(check_assembler_include_invalidation(root, env, accache,
                                                            sccache, gcc, hits))
        results.extend(check_gcc_nested_specs(root, env, accache, sccache, gcc, hits))
        results.extend(check_gcc_profile_note_outputs(root, env, accache,
                                                      sccache, gcc, hits))
        results.extend(check_gcc_auto_profile_inputs(root, env, accache,
                                                     sccache, gcc, hits))
        results.extend(check_field_named_include(root, env, accache, sccache,
                                                 gcc, clang, hits))
        results.append(check_absolute_inline_assembler_input(root, env, accache,
                                                              sccache, gcc, hits))
        results.extend(check_inline_assembler_inputs(root, env, accache,
                                                     sccache, gcc, clang, hits))
        results.extend(check_clang_vfs_overlays(root, env, accache,
                                                sccache, clang, hits))
        results.extend(check_clang_profile_use(root, env, accache, sccache,
                                               clang, hits))
        results.extend(check_clang_sanitizer_ignorelist(root, env, accache,
                                                        sccache, clang, hits))
        results.extend(check_clang_xray_lists(root, env, accache,
                                              sccache, clang, hits))
        results.extend(check_clang_profile_list(root, env, accache,
                                                sccache, clang, hits))
        results.extend(check_clang_sample_profile(root, env, accache,
                                                  sccache, clang, hits))
        results.extend(check_clang_multilib_config(root, env, accache,
                                                   sccache, clang, hits))
        results.extend(check_clang_profile_remapping(root, env, accache,
                                                     sccache, clang, hits))
        results.extend(check_clang_layout_seed(root, env, accache,
                                               sccache, clang, hits))
        results.extend(check_clang_warning_mappings(root, env, accache,
                                                    sccache, clang, hits))
        results.extend(check_clang_pass_plugin(root, env, accache,
                                               sccache, clang, hits))
        results.extend(check_clang_frontend_plugin(root, env, accache,
                                                   sccache, clang, hits))
        results.extend(check_clang_llvm_file_inputs(root, env, accache,
                                                    sccache, clang, hits))
        results.extend(check_clang_llvm_report_passthrough(root, env, accache,
                                                           sccache, clang, hits))
        results.extend(check_rust_native_archives(root, env, accache, sccache,
                                                  gcc, rustc, hits))
        results.extend(check_rust_extern_inputs(root, env, accache,
                                                sccache, rustc, hits))
        results.extend(check_rust_target_json(root, env, accache,
                                              sccache, rustc, hits))
        results.extend(check_rust_llvm_plugin(root, env, accache,
                                              sccache, rustc, clang, hits))
        results.extend(check_rust_codegen_backend(root, env, accache,
                                                  sccache, rustc, hits))
        results.extend(check_rust_replayable_reports(root, env, accache,
                                                     sccache, rustc, hits))
        results.extend(check_rust_shell_argfiles(root, env, accache,
                                                 sccache, rustc, hits))
        results.append(check_rust_shell_literal_at_passthrough(
            root, env, accache, sccache, rustc))
        results.extend(check_rust_llvm_file_inputs(root, env, accache,
                                                   sccache, rustc, hits))
        results.append(check_rust_llvm_report_passthrough(root, env, accache,
                                                          sccache, rustc, hits))
        results.append(check_rust_llvm_unknown_passthrough(root, env, accache,
                                                           sccache, rustc, hits))
        results.extend(check_rust_profile_use(root, env, accache, sccache,
                                              rustc, clang, hits))
        results.extend(check_rust_sample_profile_use(root, env, accache,
                                                     sccache, rustc, hits))
        results.extend(check_rust_sanitizer_abilist(root, env, accache,
                                                   sccache, rustc, hits))
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
