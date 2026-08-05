# Contributing to AOS

Thank you for contributing. Before opening a change, read
[`LICENSING.md`](LICENSING.md) and the repository instructions in
[`AGENTS.md`](AGENTS.md).

## Contributor agreement

Every external human contributor must accept the
[AOS External Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md)
before a contribution is merged. The contributor keeps copyright. If an
employer or another organization owns rights in the contribution, the external
contributor must first obtain authority sufficient to make every grant and
representation in the agreement. A contribution cannot be accepted without
that authority; AOS does not provide a separate organization-level agreement
path.

Current Andyl, Inc. employees contributing within the scope of their employment
are covered by Andyl's standard Confidential Information and Invention
Assignment Agreement (CIAA) and internal contribution authorization. They do
not accept the external agreement. Employee status and contribution authority
must be verified from a private Andyl record tied to the contributor's stable
GitHub user ID; a company-domain email address alone is not sufficient.
Contractors, former employees, and anyone whose employee authorization cannot
be verified follow the external-contributor path.

The Project Steward is Andyl, Inc., a Delaware corporation. Its current contact
and legal-notice instructions, agreement status, and designated acceptance
mechanism are published at <https://cla.andyl.org/aos>.

### Acceptance and enforcement

An external contribution may be merged only when the canonical frontend above
identifies the agreement and acceptance mechanism as active, the
Andyl-operated service has recorded the contributor's acceptance, and its
required repository check is passing. The service implementation and deployment
are separate from this repository.

The service and its private records must bind each acceptance to:

- the exact agreement version, its content digest, and an archived copy of the
  accepted text;
- the signer's legal name, email address, contact address, authenticated stable
  GitHub user ID, and current GitHub login;
- an unambiguous act of assent or signature, UTC timestamp, and unique record
  identifier; and
- an active, superseded, or disabled status for future contributions and the
  pull requests or commit
  identities evaluated against it.

The merge check must fail closed when an external acceptance or verified
employee authorization is absent, an identity or agreement version does not
match, an authorization is no longer active, or the verifier is unavailable or
returns an error. Maintainers must not bypass a missing or indeterminate result.
See the
[maintainer contributor-authorization policy](docs/maintainers/contributor-licensing.md)
for the complete intake and record-handling requirements.

## License by path

- Original AOS files use Apache-2.0 unless a more specific notice applies.
- `crucible-protocol` and `crucible-shmem` use `MIT OR Apache-2.0`.
- `crucible-qemu-plugin` and `crucible-qemu-trace-plugin` use
  `GPL-2.0-only`.
- Existing QEMU files and patches to them retain the applicable upstream file
  license. Never replace a more specific upstream notice with a blanket notice.
- New QEMU files follow an explicit compatible file notice when present.
  Otherwise they inherit QEMU's documented default, currently
  `GPL-2.0-or-later`. Update
  [`pkgs/emulation/qemu-patches/LICENSES.md`](pkgs/emulation/qemu-patches/LICENSES.md)
  whenever the patch series starts creating or deleting a file.
- Third-party code retains its own license and notices.
- The patched `qemu-crucible` package is not a standalone release root. Use the
  `crucible` aggregate when publishing; its release policy must retain the
  matching `qemu-crucible-source` output in the published closure. The
  publisher scans transitive closure members, so a plugin or wrapper does not
  bypass this requirement.

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
