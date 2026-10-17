// Launch only the fixed private selected source owner; never a generic proxy.
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { startOwnedSource } from "./source-hold.mjs";

if (process.argv.length !== 3) throw new Error("one private source selection required");
const file = await open(process.argv[2], constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
let raw;
try {
  const before = await file.stat();
  if (!before.isFile() || before.uid !== process.getuid() || before.nlink !== 1
      || (before.mode & 0o077) || before.size > 65536) throw new Error("source input custody differs");
  raw = await file.readFile();
  const after = await file.stat();
  if (raw.length !== before.size || ["dev", "ino", "size", "mtimeMs", "ctimeMs"].some(key => before[key] !== after[key])) {
    throw new Error("source input changed");
  }
} finally {
  await file.close();
}
const owner = await startOwnedSource(JSON.parse(raw));
for (const signal of ["SIGTERM", "SIGINT"]) process.once(signal, () => { owner.stop(); });
