# andyl/testing release retention policy

Policy id: `andyl-testing-retention-v1`

This is the public retention policy for releases published to the
`andyl/testing` registry. It is versioned: a change to this text is a new
policy id, never an edit in place.

## Corresponding source

Every distributed binary is retained together with the complete corresponding
source required to rebuild it. Release planning records this as
`require_corresponding_source`, and canonical releases may not set it false.

This obligation covers the patched QEMU distributed with the Crucible suite,
whose matching `qemu-crucible-source` output is co-retained by enforced release
policy.

## What is retained

For every published release:

- the signed release plan, manifest, and evidence bundle;
- every distributed artifact and its corresponding source store roots;
- the TUF metadata and channel partition state published for the release;
- the qualification evidence that admitted the release, including the retained
  non-public predecessor snapshot the update and rollback cases start from.

## How long

Artifacts and evidence are retained for as long as any published channel
partition resolves to the release, and for one year after the last partition
stops resolving to it.

A retained non-public qualification predecessor is kept for as long as any
release that named it remains retained.

## Experimental status

`andyl/testing` is an experimental registry. It may be rebuilt from scratch,
and a trust-root epoch reset withdraws its published releases. A reset does not
shorten the retention of evidence for releases that were published before it.
