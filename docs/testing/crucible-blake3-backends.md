# Local BLAKE3 backend qualification

The local component check `checks.crucible.ram.blake3Backends` compares the
actual persistent RAM and checkpoint identities from every production-enabled
BLAKE3 backend available on the machine. It does not qualify VM behavior,
native paging, guest equivalence, resource custody, or performance.

Run it only in an authorized qualification scope using the ordinary release
build identity and no remote builders:

```text
aos-dev --release build check crucible.ram.blake3Backends --no-out-link --option builders ''
```

The check disables substitution of its own CPU-dependent execution receipt.
Dependencies still use the ordinary source-built AOS packages and locked vendor
inputs. Cargo targets and the private Cargo home live in the build directory;
there are no shared compiler-cache mounts, wrappers, or incremental compilation.
A daemon-wide static cache mount requires the separate qualification builder
policy described in the repository instructions. Do not use this command to
bypass an unresolved build or cache approval.

## Actual dispatch controls

The pinned Rust library is BLAKE3 1.8.5, with workspace features `std,pure`.
`pure` selects Rust x86 intrinsics instead of assembly; it does **not** force
portable dispatch. The library still detects AVX2, SSE4.1, and SSE2 in descending
order. The upstream `no_*` testing features short-circuit the corresponding
runtime detectors, so separate Cargo invocations establish these exact ceilings:

| Requested backend | Additional dependency testing features |
| --- | --- |
| Portable | `no_sse2,no_sse41,no_avx2,no_avx512` |
| SSE2 | `no_sse41,no_avx2,no_avx512` |
| SSE4.1 | `no_avx2,no_avx512` |
| AVX2 | `no_avx512` |

No features or backend setters are added to production APIs. The check passes
upstream dependency features on the Cargo command line and keeps independent
target directories. `RUSTFLAGS` supplies only the SQLite library rpath; it does
not pretend to select a hashing backend.

The fixture observes the upstream benchmark-only public `Platform::detect`
result used by ordinary `Hasher::new` and `hash`. It checks CPU support before
creating fixture RAM or stores, and refuses a selected-backend mismatch. A
backend unsupported by the CPU or architecture records `not-executed` and emits
no identity transcript. Its ordinary test-runner return is never counted as
backend execution. Portable must execute, and every supported requested backend
must execute and match its transcript.

Production `pure` disables AVX512 and AArch64 NEON in the pinned build script.
Those rows explicitly record `disabled-by-production-pure`; this check makes no
claim that either implementation ran. A production feature change invalidates
the check's feature guard and requires revisiting the matrix. A pinned library
change likewise requires checking its actual dispatch and build implementation.

Primary implementation references are the pinned upstream
[`platform.rs`](https://github.com/BLAKE3-team/BLAKE3/blob/1.8.5/src/platform.rs),
[`build.rs`](https://github.com/BLAKE3-team/BLAKE3/blob/1.8.5/build.rs), and
[`rust_avx2.rs`](https://github.com/BLAKE3-team/BLAKE3/blob/1.8.5/src/rust_avx2.rs).
The version and checksum are retained in `crates/Cargo.lock`.

## Fixture and evidence

All profiles run the same private CAS test, using the existing admitted SQLite
store fixture and its original decoder resource scopes. The fixture:

- Hashes canonical logical pages across block and chunk boundaries, including
  final partial pages and a full 4096-byte page.
- Builds real persistent trees for main RAM, device RAM, and immutable images;
  compares all three scoped root records with the independent full-byte oracle.
- Captures and updates an actual exact RAM checkpoint, checks the old checkpoint
  remains readable, verifies changed paths and proofs, and reopens and verifies
  the stored successor.
- Emits canonical page digests, scoped record bytes, proof bytes, checkpoint
  object IDs, and complete canonical checkpoint envelope bytes.
- Refuses corrupted page proofs and corrupted checkpoint identity preimages.

The exact checkpoint contains 258 regions. Its genuine canonical storage
manifest must exceed 32 KiB, so the actual `ContentId::for_bytes` publication
path supplies enough contiguous input for wide hashing. This matters because a
4096-byte page alone does not reach the AVX2 eight-chunk kernel; its selected
AVX2 dispatch delegates short work to SSE4.1. The harness checks persistent
format behavior through the genuine long manifest rather than substituting a
standalone arbitrary hasher vector. The size check fails if the fixture stops
reaching that production call shape.

`matrix.tsv` distinguishes executed, unsupported, and disabled backends. Each
executed profile has a complete log and a 30-row identity transcript under
`evidence/`; every transcript must match portable byte for byte. Neither
random resource identities, clocks, process IDs, temporary paths, nor test
runner messages enter the compared transcripts. The result explicitly limits
qualification to local component identities, and does not advertise backend
coverage from an unexecuted row.

Authoring or reviewing this check provides no execution evidence. Until the
hermetic check runs, every backend row remains **UNRUN**.
