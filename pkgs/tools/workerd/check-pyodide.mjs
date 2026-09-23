/** Exercise the built interpreter and embedded libraries without package downloads. */
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const directory = resolve(process.argv[2]);
const { loadPyodide } = await import(pathToFileURL(`${directory}/pyodide.mjs`));

// This test uses only the bundled standard library. An empty package index
// prevents optional package resolution from contacting an external registry.
const runtime = await loadPyodide({
  indexURL: directory,
  lockFileContents: {
    info: {
      arch: "wasm32",
      abi_version: "2026_0",
      platform: "emscripten_5_0_3",
      version: "314.0.0",
      python: "3.14.2",
    },
    packages: {},
  },
});

const result = runtime.runPython(`
import bz2
import ctypes
import lzma
import sqlite3
import sys
import zlib
from compression import zstd
from xml.etree import ElementTree

assert sys.version_info[:3] == (3, 14, 2)
payload = bytes(range(256)) * 16
for codec in (bz2, lzma, zlib, zstd):
    assert codec.decompress(codec.compress(payload)) == payload

with sqlite3.connect(":memory:") as database:
    database.execute("create table values_to_sum (value integer)")
    database.executemany("insert into values_to_sum values (?)", [(19,), (23,)])
    assert database.execute("select sum(value) from values_to_sum").fetchone() == (42,)

assert ElementTree.fromstring("<result>42</result>").text == "42"
assert ctypes.c_int(42).value == 42
sum(range(10))
`);
assert.equal(result, 45);
assert.equal(await runtime.runPythonAsync("import asyncio\nawait asyncio.sleep(0)\n6 * 7"), 42);
console.log("Pyodide interpreter, compression, SQLite, XML, ctypes, and async checks passed");
