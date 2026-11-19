# Static release surfaces

This page describes publication surfaces that are not an AOS Hub: the
supported origin schemes and surface pairs, the surface identity file, the
published layout, and how channels and receipts work on a static origin. It
is part of the [canonical release coordinator](canonical-releases.md)
reference.

## Static surfaces

A static surface is a publication endpoint that is not an AOS Hub. It is a
directory tree served by an ordinary origin, written directly by the
coordinator and read back anonymously. Nothing on the static path calls a Hub,
and a registry whose surfaces are both static needs no Hub deployment at all.

| Origin scheme | Upload | Read-back | Compare-and-swap |
| --- | --- | --- | --- |
| `file://` | Direct filesystem writes | The same path, or an `https://` read-back origin | Exclusive `create_new` lock file plus temporary-file rename |
| `s3://bucket/prefix` | S3 API with the AWS default credential chain and the surface's `s3_region`, `s3_profile`, and `s3_endpoint` | `readback_origin`, required | `If-Match` and `If-None-Match` conditional writes against the returned ETag |
| `sftp://host/path` | SFTP with a configured credential | `readback_origin`, required | Temporary write, rename, and exclusive-create lock |
| `https://` | Not supported | Accepted only as a `readback_origin` | Not applicable |

### Supported surface pairs

| Staging | Production | Accepted |
| --- | --- | --- |
| Hub | Hub | Yes |
| Hub | Static | Yes |
| Static | Static | Yes |
| Static | Hub | No: a production Hub cannot yet verify receipts from a static staging surface |

Planning rejects the unsupported pair and requires the two surfaces to have
different identities.

### Surface identity

The file `.aos-surface` at the read-back root contains the surface identity
string, and it must equal the plan's surface `identity`. `new` reads it when
freezing the plan; `publish`, `channel advance`, and `timestamp publish` read it
before and after every mutation. Provision it once when creating the surface
and never reuse an identity for a different origin. A new identity is a new
surface: its `hub-restore` and `key-rotation` fitness attestations must be
recorded again.

### Layout

`step publish` projects the captured bundle into the machine surface layout,
driven by the manifest's artifact records rather than path prefixes:

| Bundle path | Surface path |
| --- | --- |
| `registry/<path>` | `<path>` |
| `cache/nix-cache-info` | `nix-cache-info` |
| `cache/narinfo/<hash>.narinfo` | `<hash>.narinfo` |
| `cache/nar/...` | `nar/...` |
| Image, container, evidence, closure, and source artifacts | `releases/<role>/<version>/...` at each artifact's declared public path |
| Signed manifest envelope | `releases/<role>/<version>/release-manifest.json` |

`<role>` is the release's TUF delegated role (`edge`, `candidate`, or
`stable`). The composed surface also carries `tuf/`, where `tuf/timestamp.json`
is the only mutable object and every versioned metadata file is immutable, and
the release record beside the manifest for production destinations. Channel
state lives under `channels/<name>/`: one object per partition
(`channels/<name>/00` through `channels/<name>/ff`) and the generation record
`channels/<name>/generation` (`aos.release.channel-generation/v1`).

Immutable objects are uploaded before mutable ones. The command then reads
every object back from the read-back origin, compares its digest and size, and
exercises range requests where the origin is HTTP.

### Channels and receipts

A channel advance on a static surface reads the current generation record,
takes the scheme's lock or conditional write, writes the ring's partition
objects and the successor generation record, uploads, and reads both back. A
generation that changed since the operator observed it fails closed without
writing partitions. Partition objects are signed by the plan's `registry` role
using the Git tag signing context; the signer request binds the destination,
ring, and partition range.

Publication and channel receipts have one shape on every surface:
`aos.release.publication-receipt/v1` and `aos.release.channel-receipt/v1`
documents naming the surface kind, surface identity, destination, and the
predecessor receipt they follow; channel receipts also name the ring. A static
surface signs them locally with the plan's `surface-receipt` role, which Hub
surfaces never use. A Hub deployment issues the same documents signed by its
own receipt keys, and the coordinator records both kinds verbatim.

TUF timestamp publication on a static surface replaces `tuf/timestamp.json`
with the same compare-and-swap and read-back.

A static surface creates a channel's `channels/<name>/` objects on its first
advance. A Hub surface does not: every channel, including a per-train channel
such as `stable-2026.9`, must already exist as an indexed row in the Hub's
`channels` table before `step channel advance` succeeds. The Hub indexes
channels from the registry publications it serves, so a new per-train channel
must appear in an indexed publication on that deployment before its first
advance; otherwise the advance fails closed.
