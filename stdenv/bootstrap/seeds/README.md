# AOS bootstrap seed

This directory contains the compiler-bootstrap root of trust for AOS. The
committed `hex0` executable is the only program in the toolchain ladder that is
not built from source by an earlier AOS program. It converts an annotated text
file of hexadecimal bytes into an executable or other binary file.

The seed is not a cryptographic key and it is not the whole platform trust
base. The CPU, firmware, host Linux kernel, Nix evaluator and daemon, configured
substituter-signing policy, storage, and source review remain trusted. A
malicious seed could nevertheless taint every compiler and package built after
it, so a normal successful build is not evidence that the seed is trustworthy.

## Reviewed artifacts

| File | Role | SHA-256 |
| --- | --- | --- |
| `hex0` | Committed 501-byte ELF32/i386 executable | `b7f8a8558f76c744b90c7e20b5e1edc6c89b57ba5edd3e727a256fcae2ea68ab` |
| `hex0-i386.hex0` | Canonical, byte-for-byte source for the executable | Review with the executable |
| `hex0-i386.S` | GNU assembler cross-check for the 385-byte code region | Review with the canonical source |

`stage0-seeds.nix` imports the executable through a pinned recursive Nix hash,
which covers both its bytes and executable marker atomically. The raw SHA-256
above remains the format-independent review identifier.

The seed and its two source representations are Apache-2.0 licensed. The other
sources in this directory retain their per-file licenses.

## Command and input language

The only accepted invocation is:

```text
hex0 INPUT OUTPUT
```

Exactly two path arguments are required. The input language consists of:

- hexadecimal nibbles `0`-`9`, `A`-`F`, and `a`-`f`;
- the separators space, horizontal tab, line feed, and carriage return; and
- comments beginning with `#` or `;` and extending through line feed or EOF.

Success requires an even number of hexadecimal nibbles. Separators and comments
may occur between the two nibbles of a byte. Every other byte is invalid. The
output is the sequence of decoded bytes in input order.

For example:

```text
# ELF magic
7F 45 4c 46
```

produces the four bytes `7f 45 4c 46`.

## File and failure contract

The seed opens the input before touching the output. It creates the output with
`O_WRONLY | O_CREAT | O_EXCL`, so an existing file, dangling symlink, or input
path reused as the output is never truncated. It applies mode `0700` with
`fchmod`, independently of the process umask.

The program returns zero only after all input has been validated, every output
byte has been written, and both `fsync` and `close` have succeeded. It retries
`read`, `write`, `fsync`, and cleanup `unlink` after `EINTR`. Any other syscall
failure, invalid input byte, incomplete final byte, or argument error returns
one. Every detected failure after output creation attempts to unlink the
partial file before exiting.

The program intentionally emits no diagnostic text. A single failure exit code
keeps the root executable small, deterministic, and free of a second output
channel. Higher bootstrap layers provide contextual diagnostics.

These pathname guarantees assume the output directory is not concurrently
modified by an adversary. That is the environment provided by a Nix build: the
builder has private output paths, and Nix publishes them only after successful
exit. The seed is not a transactional general-purpose file writer. In a shared,
hostile directory, another process could rename or replace the path between
creation and cleanup; a reader could observe the file before `fsync`; and an
uncatchable process termination could leave it behind. The program syncs file
contents, not the parent directory entry. Callers outside Nix must provide the
same exclusive-directory and failed-output cleanup guarantees.

## ELF and machine-code invariants

The executable is 501 bytes:

```text
0x0000..0x0033  ELF32 header
0x0034..0x0053  one PT_LOAD program header
0x0054..0x0073  one PT_GNU_STACK program header
0x0074..0x01f4  385-byte code region
```

The load segment is readable and executable but not writable. The stack is
readable and writable but explicitly not executable. There are no sections,
dynamic loader, libraries, relocations, writable globals, referenced string
literals, non-code payload, or bytes outside these regions.

The only syscalls are the Linux i386 ABI operations `exit`, `read`, `write`,
`open`, `close`, `unlink`, `fchmod`, and `fsync`. All branch and call targets
are fixed instruction boundaries. Input controls only one four-byte stack slot
whose address is passed to one-byte reads and writes.

Register and stack ownership at parser control-flow boundaries after output
creation is:

| Register | Invariant |
| --- | --- |
| `esi` | Open input file descriptor |
| `edi` | Open output file descriptor |
| `ebp` | `-1` when no nibble is pending, otherwise a value in `0..15` |
| `esp[0]` | Four-byte allocation whose first byte is the I/O buffer |
| `esp[4]` | Preserved output pathname used only for failure cleanup |

The byte-emission block temporarily shifts `ebp` into `0..240` before combining
the low nibble, then resets it before returning to the parser. A helper `call`
temporarily places its return address at `esp[0]`, moving the buffer and saved
path to `esp[4]` and `esp[8]`; the helper addresses the buffer accordingly and
returns before any cleanup branch is reachable. Syscall argument registers are
reloaded before every syscall. Input bytes are loaded with an explicit zero
extension before classification; no decision depends on stale high register
bits.

## Editing the seed

Never edit the `hex0` binary directly and never update its digest merely to
make an assertion pass.

1. Amend this contract first if behavior changes.
2. Add or update positive, negative, and injected-failure tests.
3. Edit `hex0-i386.S` for a readable control-flow implementation.
4. Edit `hex0-i386.hex0`, recording every instruction and byte offset.
5. Assemble the `.S` code region and compare it with bytes `0x0074..0x01f4`
   of the canonical source.
6. Decode `hex0-i386.hex0` with at least two independently implemented tools.
7. Compare both candidates byte-for-byte, disassemble the result, and account
   for every byte and control-flow edge.
8. Run the seed validation check and the complete local test surface.
9. Only after review, replace `hex0` and update the pinned digest.

Host tools may be used during an explicit audit ceremony as independent
comparators, but they must not become build dependencies. Repository checks use
only AOS packages built from source. Self-reproduction and downstream checks
detect drift; they do not defeat a seed deliberately written to recognize its
own tests. Human byte review and independent external reconstruction remain
mandatory for changes to this trust root.

## Required validation

The `checks.build.bootstrap-seed` gate verifies:

- the pinned size, digest, executable bit, ELF headers, RX load segment, and NX
  stack;
- canonical-source self-reproduction;
- canonical-output equivalence with a separately implemented C reference
  decoder compiled by the AOS toolchain;
- differential agreement with that reference for every possible byte in three
  parser contexts, plus rejection after a partial write;
- exact agreement between the `.S` code region and canonical bytes;
- positive vectors covering comments, separators, mixed case, and empty input;
- rejection and cleanup for malformed input, missing arguments and files,
  existing outputs, symlinks, same-path operation, and odd nibbles;
- correct operation when file descriptor numbers exceed 255;
- retry after injected `EINTR` and cleanup after injected read, write, mode,
  synchronization, and close failures; and
- exact hashes of the immediate `kaemNix`, `mkdir`, and `ln` bootstrap tools.

Those three immediate derivations are also recursive fixed-output derivations,
so Nix rejects unexpected bytes or executable-mode changes before they can
drive the next bootstrap stage.

## Architecture boundary

This seed and the immediate stage0 chain execute as i386 Linux programs. They
are supported on i686 and x86_64 Linux with IA-32 execution enabled. They cannot
serve as native AArch64 builders. `stage0-seeds.nix` therefore fails evaluation
when forced for another build CPU instead of creating a derivation that cannot
execute.

The later source-bootstrap ladder relies on historical x86-only compiler stages,
so an AArch64 seed alone would not make this chain native. AOS therefore treats
x86 execution as a deliberate bootstrap constraint. An undeclared host emulator
is not an acceptable substitute in the hermetic bootstrap. The repository audit
gate uses modern AOS-built validation tools and currently runs on x86_64 Linux;
that narrower gate platform does not narrow the seed's i686 execution contract.
