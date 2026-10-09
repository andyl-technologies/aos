# Closed gem5 process-image capture evidence

This evidence covers the source-built native64 DMTCP capture mechanism and its
bounded independent closure collector. The admitted witness workload is the
fixed freestanding x86_64 or AArch64 checksum ELF with one O3 CPU, classic caches,
private RAM, DDR3 memory and no external guest input. It does not establish
full-system/device parity, arbitrary executable support, complete typed model
diagnostics or runtime service admission.

## Immutable source and artifacts

DMTCP 4.2.0 revision `f8009ce7b4ad211311ca2f72a929b975e4aa1155` is built from
source with the original restart bounds and signal parsing fixes and the five
capture patches below. Source notices remain LGPL-3.0-or-later; declarations in
its public-domain interface header preserve that dedication.

| Capture patch | SHA-256 |
| --- | --- |
| `capture-context-ledger.patch` | `ed598155a669a55cec9f2b337fd00bc4921ae7db3116f5b84c668c22a404e647` |
| `capture-kernel-thread-identity.patch` | `be618f879eacda1d68cbdd5f3c9361de2d87f4f455532fdaa47507453f4f6c38` |
| `capture-descriptor-ledger.patch` | `abea7f81d4eac838cac748c89d2d6cfb92a475c790e4089d28df5315381ff4c7` |
| `capture-mapping-ledger.patch` | `616fdbd6f92ef2666dd1c0fc4c18b5fc67445ea1c5be3302211ae68034e443c7` |
| `capture-file-mapping-ledger.patch` | `def4cbd0b6dae9165a37ad82caf492eab94f3624949852683476ad39cb0b3ec3` |

The exercised toolkit is `rpjbjf6ydsiz6v4675v6y5wa2mrrc98w-dmtcp-4.2.0`.
Its `libdmtcp.so` SHA-256 is
`38e25a4246d2e756239a49a766169165c10e133eb4ebbf51a00255d134def58f`;
its `libdmtcp_ipc.so` SHA-256 is
`54c32ff98b1fc837a7dbf2e3b057f0722f1d4fa66e25431a0b976a62bf1d4b98`.
The installed collector is
`qf0hb20a34g1bacg4fxcl62z1i9xdwh7-gem5-process-image-inventory-1`;
its installed Python implementation SHA-256 is
`b664c1032b43b3978de0b9e53823789011b875ec80d5320814cd672e77af02ba`.

Both native witnesses use gem5 `afglidl1n0zl2icjzi17yj66d5b5gyg8-gem5-25.1.0.1`,
whose executable SHA-256 is
`9a9dea18838236bf91d39e49df575bea9bf15d34d9638dfa28059cb0f4bfe91e`.
This is an immutable tested artifact; subsequent source changes require their
own native witnesses. The host ABI is x86_64 Linux 6.18.54, little endian, with
4096-byte pages. AArch64 here is the simulated guest architecture.

## Native results

For both ISAs, the owner stopped after 5000 actual events without draining.
The collector authenticated the original native maps, saved thread contexts,
complete descriptor roster, temporary shared-file transformation and immutable
supplementary guest ELF. Every native ledger body was checked against captured
image bytes. Both closure receipts report `complete=true`, no omissions, and
`modeled_diagnostics_complete=false`.

| Guest ISA | Original maps | Captured regions | Native threads | Original FD records | Image bytes | Image SHA-256 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `x86_64` | 678 | 672 | 2 | 9 | 936771584 | `4f9f19512106e2fd1a995c66cb1e9f6f554e22367500f7e5c454331ce8e2a0b5` |
| `aarch64` | 681 | 675 | 2 | 9 | 1129885696 | `823dc2c5862b2cd22e246d43ace913ab88400c269a72d4573a31e477c8ee216c` |

Each source then exited, its original private resource directory was deleted,
and two concurrent fresh processes independently reconstructed the same capture.
They reconnected through fresh authenticated control endpoints and preserved the
original cut, native event positions, publication birth metadata, future output
suffix and checksum. Neither reconstruction depended on a living source.

## Validation and limits

The source-built collector package passes 23 format/custody adversarial tests.
Its native mechanism check independently compares the live kernel task roster,
then verifies native thread/descriptor/map/FileConnection bodies and saved file
contents after source exit. The DMTCP package also passes its durable continuation
and two independent reconstruction checks. Reproduction builds disable remote
builders:

```text
aos-dev --release build package gem5-process-image-inventory --no-out-link --option builders '' --cores 128
```

The actual owner witness uses `native-owner-check.py` with
`CRUCIBLE_GEM5_IMAGE_AUDITOR` set to the measured installed collector and the
source-built DMTCP/resource-custody artifacts. Local receipts and logs are under
`/tmp/crucible-gem5-native-witness/{x86_64,aarch64}-whole-closure-v8` and
`/tmp/rfc0025-gem5-whole-closure-{x86,arm}-v8.log`; raw images and traces are not
repository artifacts.

A collector result is evidence, not an admission token. The provider must still
bind the installed collector, actual kernel peer, exact native launch and guest
configuration, source identity, host ABI, capture lineage and event boundary in
a privately constructed certificate. Partial typed diagnostics remain partial.
Unknown configurations, host-derived guest input, shared mutable memory and
external device/FD custody must remain refused.
