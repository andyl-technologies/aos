# Pinned compiler frontend

This crate contains the GCC, Clang, and Rust argument parsers from
[mozilla/sccache](https://github.com/mozilla/sccache/tree/8396f0209d74d496b7cb27cdf323cd3ff8d4a291),
revision `8396f0209d74d496b7cb27cdf323cd3ff8d4a291` (version 0.18.0).
The original Apache-2.0 license and source copyright notices are retained.

## Extraction boundary

The complete `ARGS` tables, argument enums, generic argument iterator, GNU
response tokenizer, Rust response expansion, parse functions, and their
supporting data types are retained. No daemon, network client, cache backend,
compiler process launcher, or remote execution code is included.

The adaptation makes parser entry points and supporting fields visible to the
parent crate, replaces their surrounding compiler implementations with small
shared types, retains the Unix `OsStr` conversion helper, and removes imports
of unused server/runtime components. Rust compiler version probing and
process mocks do not belong to this crate. Rustfmt formatting is mechanical.

117 upstream tests cover the generic argument machinery and extracted parser
functions. Tests requiring sccache's process mock/server implementations were
not copied. The Nix real-compiler suite exercises the pinned, unmodified
sccache executable as an independent oracle, rather than treating these
extracted tests as sufficient evidence of behavioral compatibility.

## Updating

Update this revision and `tests/build/accache/sccache-oracle.nix` together.
Review the upstream argument tables, output descriptions, cacheability rules,
response handling, and their tests against this copy. Then run the workspace
unit tests and `checks.build.accache`, which compares direct compilation,
sccache, and accache, including restored side artifacts.

Unknown flags retain the upstream parser's behavior. An accepted flag does not
by itself establish that a new compiler's side outputs or implicit inputs are
covered; new artifact families need discovery logic and oracle fixtures.
