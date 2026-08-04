# Contributing to AOS

Thank you for contributing. Before opening a change, read
[`LICENSING.md`](LICENSING.md) and the repository instructions in
[`AGENTS.md`](AGENTS.md).

## Contributor agreement

Original contributions to AOS are accepted only after the contributor agrees
to the [AOS Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md).
The contributor keeps copyright. If an employer or another organization owns
the contribution, the contributor must obtain authority to contribute it and
the project may require a separate corporate agreement.

CLA acceptance is not operational yet. Before collecting or relying on any CLA
acceptance, maintainers must publish the current Project Steward's legal identity
and contact details and designate the acceptance mechanism. Do not substitute an
informal project name for the legal recipient on a signed agreement.

## License by path

- Original AOS files use Apache-2.0 unless a more specific notice applies.
- `crucible-protocol` and `crucible-shmem` use `MIT OR Apache-2.0`.
- `crucible-qemu-plugin`, QEMU integration loaded into QEMU, and new
  GPL-covered QEMU-side files use `GPL-2.0-only`.
- Existing QEMU files and patches to them retain the applicable upstream file
  license. Never replace a more specific upstream notice with a blanket notice.
- Third-party code retains its own license and notices.

Every contribution is licensed under the license that applies to the files it
changes. A change that moves code across a license boundary needs explicit
maintainer review and must preserve provenance.

## QEMU-side provenance

Every commit that changes QEMU, `pkgs/emulation/qemu-patches/`,
`crucible-qemu-plugin`, or other in-QEMU code must include a Developer
Certificate of Origin sign-off:

```text
Signed-off-by: Legal Name <email@example.com>
```

Add it with `git commit -s`. The sign-off certifies the Developer Certificate
of Origin at <https://developercertificate.org/>; it is separate from the CLA.
Do not add automated-tool attribution or non-human co-author trailers.

## Crucible boundary checklist

A change that touches the Crucible/QEMU boundary must demonstrate that:

- the host and QEMU remain separate processes;
- socket control and shared-memory data paths use the versioned public ABI;
- shared memory contains no pointers, function tables, QEMU structures, or
  compiler-private Rust layouts;
- in-QEMU code remains in the GPL-compatible scope;
- ABI conformance and license-boundary gates pass; and
- a distributed QEMU binary has a matching corresponding-source artifact.

Guest assertion evaluation and semantics stay in the Apache host. QEMU/plugin
changes needed to observe a guest remain GPL-side and export observations only
through the versioned shared-memory or doorbell protocols.
