# Installing a reviewed live mirror purpose

Fresh uncached upstream delivery and bounded live metadata queries have a
separate review purpose. Ordinary mirror publication and pack inspection
acceptance cannot enable this path. Use the independent mirror reviewer role
already installed by the [ordinary installer](hub-mirror-acceptance-installation.md);
the live artifact uses a distinct signature domain and KV key.

## Select the complete signed chain

Run `aos-hub worker activate-hybrid-mirror-live` with the same Hybrid deployment
configuration, independently installed direct and mirror reviewer public keys,
the selected mirror acceptance KV namespace, and these required files:

- `--direct-upload-acceptance-file`: the independently signed direct prerequisite.
- `--direct-upload-guard-key-file`: the owner-private existing Native-matched
  guard role used for authenticated current deployment discovery.
- `--mirror-acceptance-file`: the complete signed ordinary mirror artifact.
- `--mirror-pack-acceptance-file`: the signed pack prerequisite linked to that
  exact ordinary artifact.
- `--mirror-live-acceptance-file`: the separately signed live-purpose artifact.

The command consumes already independently reviewed artifacts. It creates no
measurement, signature, provider credential or new trust role. Ordinary and pack
prerequisites must already be installed for the selected unchanged deployment;
this command publishes only the live record.

The live artifact must bind the complete signed ordinary artifact, exact release
pack, current source and protected profile inherited through that prerequisite.
All thirteen closed observations are required, including `bounded_metadata_query`
with genuine nonzero provider dispatch and bounded query/result commitments.
Hosted observations, actual memory samples below the whole-Worker 128 MiB ceiling,
zero Native bulk bytes and zero destination mutations remain mandatory. Unknown,
incomplete, controlled or wrongly signed reports refuse installation.

## Preserve independent limits and original cutoffs

The live full-stream limit comes from the separately measured artifact and cannot
exceed the ordinary mirror's accepted maximum. The fixed stream lifetime is 600
seconds and readers use 64 KiB chunks. Pack inspection retains its own encoded
pack/index and decoded graph/object limits; live streaming does not enlarge them.
The required bounded metadata query observation remains at most 256 KiB. None of
these limits authorizes raw pack or NAR bytes through Native.

The installer authenticates actual deployment source, script, raw managed profile,
clock, queues and direct verifier before publication. It rechecks the full signed
chain and immutable cutoffs after every awaited staging operation and immediately
before and after KV publication. Staged output is created exclusively with mode
0600 in a private temporary directory; an existing file is never overwritten.
The record key is `accepted-mirror-live-v1/<full-signed-ordinary-artifact-sha256>`
under the existing `HUB_MIRROR_ACCEPTANCE` binding.

A failure after a KV write may leave that exact reviewed record published. The
command does not remove or infer settlement from that failure. Expired evidence
cannot authorize new dispatch; deployment changes require corresponding reviewed
artifacts. Successful publication establishes this operator step only. Genuine
live streaming, query, cancellation, concurrency, memory, CPU and wall-time
qualification remain separate acceptance gates.
