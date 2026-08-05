# Contributor authorization

This policy is the maintainer procedure for deciding whether a contribution may
be merged. It complements the public contributor instructions in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md), the
[`AOS External Contributor License Agreement`](../../CONTRIBUTOR_LICENSE_AGREEMENT.md),
and the repository license map in [`LICENSING.md`](../../LICENSING.md).

The Project Steward is Andyl, Inc., a Delaware corporation. Contribution
authorization, current legal-notice instructions, agreement status, and the
designated acceptance mechanism are published through
<https://cla.andyl.org/aos>.

## Choose the contribution path

| Contributor | Required authority | Maintainer evidence |
| --- | --- | --- |
| Current Andyl employee contributing within authorized employment scope | Andyl's standard CIAA and internal contribution authorization | Current private employee-authorization record bound to the contributor's stable GitHub user ID |
| Any other human contributor, including a contractor or former employee | Active acceptance of the AOS External Contributor License Agreement | Active private acceptance record bound to the contributor's stable GitHub user ID and the current agreement version |

A company email address does not establish employee status. If a current
employee contributes outside the scope authorized by Andyl, use the external
path. If an external contributor's employer or another party owns relevant
rights, the contributor must obtain permission sufficient to make all grants and
representations in the external agreement. The project has no separate
organization-level agreement path; reject the contribution if the individual
cannot make those grants.

The DCO sign-off required for QEMU-side changes is additional evidence of
provenance. It does not replace either authorization path.

## External acceptance contract

The external acceptance service is implemented and deployed outside this
repository. External contributions may be merged only when the canonical
frontend identifies the agreement and acceptance mechanism as active and the
repository check is enabled and passing. The stable project URL above is
authoritative for the current agreement status and contact frontend; deployment
details remain outside this repository.

For every acceptance, the service must retain a private record containing:

- the agreement version, exact content digest, and an immutable archived copy
  of the accepted agreement text;
- the signer's legal name, email address, contact address, authenticated stable
  GitHub numeric user ID, and GitHub login at acceptance;
- the affirmative act of assent or signature, its UTC timestamp, and a unique
  transaction or record identifier;
- whether the acceptance is active, superseded, or disabled for future
  contributions; and
- the pull requests, commit authors, and commit identities evaluated against
  the record.

Keep agreement text and its version in this public repository. Keep personal
acceptance records and the employee-authorization registry private with access
limited to the Project Steward's designated legal and operational
administrators. A new material agreement version must preserve the prior text
and records and require a new acceptance before later external contributions are
merged.

## Merge enforcement

The required repository check must evaluate every human contributor represented
in a pull request, including commit authors and credited co-authors. It must use
the stable GitHub numeric user ID as the identity key; mutable logins and email
domains are supporting attributes only.

Fail closed and do not merge when:

- neither a current employee authorization nor an active external acceptance
  matches a contributor;
- the contributor identity, agreement version, or accepted content digest does
  not match;
- the acceptance or employee authorization is disabled or superseded;
- a commit or co-author identity cannot be resolved; or
- the verifier is unavailable, times out, or returns an indeterminate result.

Do not bypass the check manually. Correct the underlying identity or record,
then rerun it. Service recovery must restore the complete agreement history and
authorization records before the check returns passing results.

## Maintainer checklist

Before merge:

1. Confirm that every human contributor resolves to exactly one authorization
   path.
2. Confirm that the required authorization check passes for the current pull
   request head.
3. For QEMU-side changes, confirm that each applicable commit also carries a
   valid DCO `Signed-off-by` line.
4. Review third-party material and cross-license-boundary changes under
   [`LICENSING.md`](../../LICENSING.md).
5. Never copy private acceptance or employee records into an issue, pull
   request, commit, build artifact, or public log.
