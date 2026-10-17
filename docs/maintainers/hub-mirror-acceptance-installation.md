# Installing reviewed Hybrid mirror purposes

Hybrid managed R2 mirroring requires independently reviewed ordinary mirror
evidence. Pack inspection additionally requires its own reviewed artifact linked
to the complete signed ordinary mirror artifact. Installing the existing direct
upload acceptance alone does not enable either purpose.

## Configure trust before measurement

Use the normal `aos-hub worker render-hybrid-config` or `install-hybrid` configuration
arguments to select both:

- `--mirror-qualification-public-key-file`: an independently selected Ed25519
  reviewer public key in hexadecimal text.
- `--mirror-acceptance-namespace-id`: the operator-selected KV namespace for
  mirror and pack acceptance records.

These arguments render `HUB_MIRROR_QUALIFICATION_PUBLIC_KEY` and the separate
`HUB_MIRROR_ACCEPTANCE` binding. They require managed R2 profile coordinates and
independently installed direct reviewer trust. No accepted flag is generated.

The installer places the independently supplied
`--direct-upload-guard-key-file` under both `HUB_DIRECT_UPLOAD_GUARD_KEY` and
`HUB_MIRROR_GUARD_KEY`. Native uses that same selected guard role for the two
purpose-separated protocols. Its material must differ from ingress, storage-work,
journal and qualification control keys. The storage-work producer key never
supplies guard authority. Protected keys remain owner-controlled private files
and reach Wrangler through its existing secret input path. An update may preserve
existing required secret bindings without reading their values; adding mirror
trust still requires the mirror guard binding to exist or be supplied.

Measure the actual unchanged deployment and protected profile. The ordinary
mirror and pack maintainership guides define the required hosted observations,
whole-Worker memory and runtime budgets, privacy policy and release identity.
Controlled runtime reports and unknown observations cannot be installed as
production acceptance. This command does not sign reports or create provider
credentials.

## Publish already reviewed artifacts

Run `aos-hub worker activate-hybrid-mirror` with the same Hybrid configuration,
including the independently signed direct prerequisite, installed direct and
mirror public verifier selections, and:

- `--direct-upload-guard-key-file` for authenticated deployment discovery;
- `--mirror-acceptance-file` for the signed hosted ordinary mirror artifact;
- optionally, `--mirror-pack-acceptance-file` for the separately signed pack
  artifact linked to that exact ordinary artifact.

The command reads bounded closed JSON documents and authenticates current Worker
source, script version, profile, policy, clock and queue pins through the existing
protected discovery protocol. It validates every selected artifact before the
first KV write. After each awaited staging or prior KV operation, it authenticates
the installed deployment again and rechecks the original immutable validity
windows before the next write. It publishes version-specific records without
redeploying the measured Worker.

Missing pack evidence leaves pack inspection unavailable. A malformed optional
pack document refuses the whole selection before publication. A provider write
failure can leave a valid subset installed; exact reinstallation is safe while
the original artifacts remain valid. Deployment changes require matching new
measurements and reviewed artifacts. Expiry does not renew permission or settle
an unknown provider effect; retained originals and metadata-only recovery remain
governed by their existing protocols.

Successful record publication establishes this installation step only. Actual
production mirror/pack round trips, guarded Native SQL publication, restart and
unknown-effect recovery, and the hosted memory/CPU/wall-time budget remain
separate acceptance gates.
