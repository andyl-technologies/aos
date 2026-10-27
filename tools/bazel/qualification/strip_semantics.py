"""Checks stripping using actual source-built Rust/C compilation and ELF output."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def run(command):
    """Requires successful declared-tool execution with bounded runtime."""
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)


def inspect(rustc, cc, readelf, directory):
    """Checks implicit strip=none and stripping of linked native debug sections."""
    source = directory / "strip_probe.rs"
    source.write_text('fn main() { println!("strip profile probe"); }\n')
    native = directory / "native.c"
    native.write_text(
        "__attribute__((constructor)) static void native_marker(void) {\n"
        "    volatile unsigned long value = 7;\n"
        "    (void)value;\n"
        "}\n"
    )
    native_object = directory / "native.o"
    native_command = [str(cc), "-g", "-O0", "-c", str(native), "-o", str(native_object)]
    run(native_command)

    output = directory / "strip-probe"
    common = [str(rustc), "--crate-name=strip_probe", "--edition=2024", "-Copt-level=0",
              "-Clinker=" + str(cc), str(source), "-o", str(output)]
    variants = {
        "implicit_none": ["-Cdebuginfo=2"],
        "explicit_none": ["-Cdebuginfo=2", "-Cstrip=none"],
        "rust_stripped": ["-Cdebuginfo=2", "-Cstrip=debuginfo"],
        "native_unstripped": ["-Cdebuginfo=0", "-Cstrip=none", "-Clink-arg=" + str(native_object)],
        "native_stripped": ["-Cdebuginfo=0", "-Cstrip=debuginfo", "-Clink-arg=" + str(native_object)],
    }
    binaries = {}
    records = {}
    for name, flags in variants.items():
        command = [*common, *flags]
        run(command)
        binaries[name] = output.read_bytes()
        sections_command = [str(readelf), "--sections", "--wide", str(output)]
        section_output = run(sections_command).stdout
        sections = sorted(set(re.findall(r"\[\s*\d+\]\s+(\S+)", section_output)))
        execution = run([str(output)])
        if execution.stdout != "strip profile probe\n":
            raise ValueError("strip fixture program behavior differs: " + name)
        if ".symtab" not in sections:
            raise ValueError("debug-information stripping removed the ordinary symbol table: " + name)
        expect_debug = name in {"implicit_none", "explicit_none", "native_unstripped"}
        if (".debug_info" in sections) != expect_debug:
            raise ValueError("native strip/debug section behavior differs: " + name)

        records[name] = {
            "command": command, "sections_command": sections_command,
            "sections": sections, "section_output_sha256": hashlib.sha256(section_output.encode()).hexdigest(),
            "binary_sha256": hashlib.sha256(binaries[name]).hexdigest(),
            "runtime_stdout": execution.stdout,
        }
        if name == "native_unstripped":
            debug_command = [str(readelf), "--debug-dump=info", str(output)]
            debug = run(debug_command).stdout
            if "native.c" not in debug or "native_marker" not in debug:
                raise ValueError("linked C debug information was not retained by the control")
            records[name]["debug_command"] = debug_command
            records[name]["native_source_and_constructor_in_dwarf"] = True
            records[name]["debug_output_sha256"] = hashlib.sha256(debug.encode()).hexdigest()

    if binaries["implicit_none"] != binaries["explicit_none"]:
        raise ValueError("implicit and explicit strip=none binaries differ")
    return {
        "schema_version": 1, "status": "PASS",
        "rustc_version": run([str(rustc), "--version", "--verbose"]).stdout,
        "tools_sha256": {str(tool): hashlib.sha256(tool.read_bytes()).hexdigest()
                         for tool in [rustc, cc, readelf]},
        "rust_source": source.read_text(), "native_source": native.read_text(),
        "native_compile_command": native_command,
        "native_object_sha256": hashlib.sha256(native_object.read_bytes()).hexdigest(),
        "implicit_and_explicit_none_bytes_equal": True, "variants": records,
        "limits": [
            "This native fixture establishes the pinned compiler's strip default and removal of linked C debug information when Rust debuginfo is zero.",
            "It does not compare complete application artifacts, native C/linker settings, ABI, runtime closures, or other platforms.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cc", type=Path, required=True)
    parser.add_argument("--readelf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="aos-strip-semantics-") as directory:
        report = inspect(options.rustc, options.cc, options.readelf, Path(directory))
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
