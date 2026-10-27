// Keep the Workers panic-recovery setter and its mutable Wasm instance.
import { readFileSync, writeFileSync } from "node:fs";

const path = process.argv[2];
const source = readFileSync(path, "utf8");
const preamble = /let wasm;\s*export function __wbg_set_wasm\(val\)\s*\{\s*wasm = val;\s*\}/;
if (!preamble.test(source)) {
    throw new Error("Worker bindgen glue preamble does not match the pinned generator");
}

const replacement = "\nimport __wbg_glue from './glue.js';\nlet wasm = __wbg_glue;\nexport function __wbg_set_wasm(val) { wasm = val; }\n\nexport function getMemory() {\n    return wasm.memory;\n}\n";
writeFileSync(path, source.replace(preamble, replacement));
