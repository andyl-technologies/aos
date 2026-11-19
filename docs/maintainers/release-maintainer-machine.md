# Release maintainer machine and configuration

This page describes the designated maintainer machine that runs releases: its
coordinator services, the release tooling closure, the maintainer
configuration file, and how Hub credentials are resolved. It is part of the
[canonical release coordinator](canonical-releases.md) reference; the
[release commands](release-commands.md) read the configuration described
here.

## Configure the designated maintainer machine

Enable `aos.services.releaseCoordinator` only in the private machine
configuration. Supply six hermetic wrapper programs: the manually started
content-release driver, restricted TUF timestamp renewal, encrypted backup,
clean-directory restore verification, operator alert delivery, and the
alert-delivery check. The public module deliberately contains no machine
identity or deployment-specific path.

The module creates distinct locked service accounts and state directories,
loads each role's disjoint credentials with systemd's credential mechanism,
and rejects credential sources in the Nix store. Content publication has no
timer and begins only with an operator start of
`aos-release-coordinator.service`; this is the no-CI control point. Timestamp
renewal runs every 12 hours by default, backup runs daily, and an offline
network-denied restore check runs weekly. Override calendars only if the TUF
expiry and recovery objectives remain satisfied.

A weekly `aos-release-alert-check.service` runs as the alert role, triggers
the alert path with a synthetic unit name, confirms delivery, and records a
signed `alert-delivery` fitness attestation; a successful restore check
likewise records `storage-restore`. Both land under `fitnessRoot` (default
`/var/lib/aos-release-coordinator/fitness`), a setgid directory writable by
the `aos-release-fitness` group so the release, backup, and monitor roles can
each write there, and are signed with the release-evidence signer loaded from
`fitnessCredentials`. Production destination profiles accept these machine-run
attestations for at most 14 days; operator exercises are recorded manually
with `aos maintain release fitness run <kind>` and remain valid for 90 days.

Every failed release, timestamp, backup, restore, or alert-check unit invokes
the isolated alert service with only the failed unit name and alert-role
credentials.
The content-release, backup, and restore jobs share a nonblocking advisory lock;
an overlap fails closed and alerts instead of taking an inconsistent snapshot.
Timestamp renewal uses separate state, identity, policy, and credentials and
does not acquire the content-state lock.

Deployment wrapper programs receive no command-line secrets. They resolve
credential names beneath `$CREDENTIALS_DIRECTORY`, write only beneath their
assigned state/runtime directories, and exec the documented `aos maintain release`
commands. Keep staging and production upload credentials in different
operator steps; do not place both in the manual service's credential set at
the same time.

### Release tooling environment

The coordinator never reads its own store path, the qualification
executors, or the file-backed signer from the maintainer configuration. All
come from the installed tooling closure, the flake's `release-tooling`
package: its `bin/aos` wrapper exports `AOS_RELEASE_TOOLING` naming the
closure, the closure carries one executor per platform it can qualify at
`libexec/aos-release/executors/<platform>/{run,identity}`, and it bundles the
repository's [file-backed signer](release-step-commands.md#file-backed-signer-for-registries-without-an-hsm)
at `libexec/aos-release/signer/aos-release-signer`. Enter it with
`nix develop .#release`, or install it as the `aos` every coordinator
service wrapper runs.

Without the wrapper, `aos maintain release` falls back to the `/nix/store/<name>`
root containing its own executable. A binary outside the store, such as a
development `cargo build`, has no closure: it can inspect state, but `new`,
`advance`, and every qualification step refuse to run from it. The closure
path is the `tooling` fitness binding, so all maintainer roles on a machine
must run the same closure or the restore check's attestation will not match
the operator's release.

### Maintainer configuration

The porcelain reads one `aos.release.maintainer-config/v1` TOML file: the path
in `$AOS_RELEASE_CONFIG`, else `/etc/aos-release/maintainer.toml`, else
`~/.config/aos/release.toml`. `--config` overrides the search. One
configuration serves one registry, so experimental and main keep separate files,
state directories, and credentials. Unknown keys are rejected.

```toml
schema_version = "aos.release.maintainer-config/v1"
work_root = "/var/lib/aos-release-coordinator/releases"
fitness_root = "/var/lib/aos-release-coordinator/fitness"
registry = "andyl/experimental"
protected_branch = "master"
contributor_authorization = "/etc/aos-release/release-contributor-authorization.json"
retention_policy = "/etc/aos-release/release-retention-policy.md"
restricted_operator_policy = "/etc/aos-release/restricted-operator-policy.md"
predecessor_bundle = "/var/lib/aos-release-coordinator/predecessor"
trusted_keys = ["release-evidence-v1=/etc/aos-release/keys/release-evidence-v1.pub"]

[git]
name = "AOS Release"
email = "release@aos.andyl.org"

[surfaces.staging]
kind = "hub"
origin = "https://aos.staging.andyl.org"
identity = "staging-2026-09"
receipt_keys = ["staging-publication-v1=/etc/aos-release/keys/staging-publication-v1.pub"]
# Optional: without it, AOS_TOKEN, else the active `aos hub login` profile
# for this origin (see "Hub credentials" below).
token_credential = "staging-token"

[surfaces.production]
kind = "static"
origin = "s3://aos-registry/andyl-experimental"
readback_origin = "https://cdn.example.org/andyl-experimental"
identity = "cdn-2026-09"
s3_region = "auto"
s3_endpoint = "https://s3.example.org"

[signer]
# The tooling closure's bundled aos-release-signer reads this file.
config = "/etc/aos-release/signer.json"
timeout_seconds = 900
provider_revision = "provider-2026-09"

[signer.roles.registry]
key_id = "registry-v1"
public_key = "/etc/aos-release/keys/registry-v1.pub"
verification_identity = "provider-registry-slot"

[signer.roles.surface-receipt]
key_id = "surface-v1"
public_key = "/etc/aos-release/keys/surface-v1.pub"
verification_identity = "provider-surface-slot"

[signer.roles.release-evidence]
threshold = 2
keys = [
  { key_id = "release-evidence-v1", public_key = "/etc/aos-release/keys/release-evidence-v1.pub", verification_identity = "slot-1" },
  { key_id = "release-evidence-v2", public_key = "/etc/aos-release/keys/release-evidence-v2.pub", verification_identity = "slot-2" },
]

[tuf]
root = "/etc/aos-release/tuf/root.json"
trusted_root_keys = ["root-v1=/etc/aos-release/keys/root-v1.pub"]
trusted_root_threshold = 1

[reviewer]
key_id = "release-evidence-v1"
public_key = "/etc/aos-release/keys/release-evidence-v1.pub"

[alert]
program = "/etc/aos-release/bin/alert"
destination = "oncall@example.org"
```

| Key | Meaning |
| --- | --- |
| `schema_version` | Exactly `aos.release.maintainer-config/v1` |
| `work_root` | Private directory holding one work directory per release |
| `fitness_root` | Directory holding fitness attestations as `<kind>/<performed_at>.json`; shared by every release of this registry |
| `registry` | The registry this configuration publishes; `new --registry` must equal it |
| `protected_branch` | Protected source branch; only `master` is accepted |
| `contributor_authorization` | Public contributor-authorization summary whose digest the plan binds |
| `retention_policy` | Retention policy document whose digest the plan binds |
| `restricted_operator_policy` | Restricted operator policy whose digest the plan binds without publishing it |
| `predecessor_bundle` | Verified signed bundle of the preceding release, used for the qualification predecessor, image update cases, and change scoping |
| `trusted_keys` | Independently obtained `KEY_ID=PATH` manifest verification keys |
| `git.name`, `git.email` | Required public author and committer of the registry release commit and tag. Both are published in the registry; use the maintaining organization's release identity, not a person's. The name may not contain control characters or angle brackets, and the email must be one address |
| `surfaces.<role>.kind` | `hub` or `static` |
| `surfaces.<role>.origin` | Hub origin, or static origin `file://`, `s3://`, or `sftp://` URL |
| `surfaces.<role>.readback_origin` | Anonymous `https://` or `file://` origin used for read-back when `origin` is not anonymously fetchable; required for `s3://` and `sftp://` |
| `surfaces.<role>.identity` | Hub deployment ID, or the static identity served at `.aos-surface` |
| `surfaces.<role>.receipt_keys` | `KEY_ID=PATH` keys that verify the surface's publication and channel receipts: Hub receipt keys, or the `surface-receipt` role key for a static surface |
| `surfaces.<role>.token_credential` | Optional Hub access token: a name under `$CREDENTIALS_DIRECTORY`, or an absolute path. See [Hub credentials](#hub-credentials) for the order in which it, `AOS_TOKEN`, and the `aos hub login` profile apply |
| `surfaces.<role>.s3_region`, `s3_profile`, `s3_endpoint` | S3 client settings for an `s3://` origin; credentials come from the AWS default chain |
| `surfaces.<role>.ssh_key_credential`, `ssh_password_credential` | SFTP private key or password for an `sftp://` origin |
| `surfaces.<role>.hub_schema` | Hub schema version the surface reports; the production value is the `hub-schema` fitness binding. Hub surfaces only |
| `signer.config` | Absolute path of the signer's own configuration file, handed to the signer process as `AOS_RELEASE_SIGNER_CONFIG`. Required when `executable` is absent |
| `signer.executable` | Optional absolute path of an external signer adapter, such as an HSM provider. When absent, the coordinator runs the `aos-release-signer` bundled in its [tooling closure](#release-tooling-environment). At least one of `executable` and `config` must be set |
| `signer.timeout_seconds` | Per-operation bound, 1 to 900 seconds (default 900) |
| `signer.provider_revision` | Provider policy revision frozen into every planned signer role that names none |
| `signer.roles.<role>` | One table per signer role in the plan, keyed by the role's public spelling, such as `registry`, `release-evidence`, `qualification`, `surface-receipt`, or `tuf-timestamp`. `new` freezes every table into the plan's signer roster in role-name order |
| `signer.roles.<role>.key_id`, `public_key`, `verification_identity` | Single-key form: key ID, independent public key, and pinned provider identity; means one key with threshold 1 |
| `signer.roles.<role>.keys`, `threshold` | Multi-key form: a list of `{key_id, public_key, verification_identity}` tables and the number of distinct signatures required (default 1). Use either this form or the single-key form, not both |
| `signer.roles.<role>.provider_revision` | Provider policy revision for this role; overrides `signer.provider_revision` |
| `tuf.root`, `tuf.trusted_root_keys`, `tuf.trusted_root_threshold` | Authenticated current TUF root and its independent trust inputs |
| `reviewer.key_id`, `public_key` | Release-evidence key used by `aos maintain release review` and, when present, by `aos maintain release fitness run` |
| `alert.program`, `alert.destination` | Alert delivery program and on-call destination; the section's digest is the `alert-config` fitness binding |

`predecessor_bundle`, `trusted_keys`, `[tuf]`, `[reviewer]`, and `[alert]`
may be omitted; a command that needs an omitted value refuses to run. The two
surfaces must have different identities.

Every `*_credential` key resolves to `$CREDENTIALS_DIRECTORY/<name>` or an
absolute path, is read without following links, and is trimmed. No secret
appears in the file itself.

#### Hub credentials

Every porcelain command that reaches a Hub surface (`new`, `advance`,
`publish`, and the steps they run) resolves that surface's token in this
order:

1. the surface's `token_credential`;
2. a non-empty `AOS_TOKEN`;
3. the renewable `aos hub login` profile stored for the surface origin,
   refreshed before use and before each object or multipart operation of a
   long upload.

The profile is resolved exactly as the `aos hub` commands resolve it, from
`$AOS_CONFIG_HOME/hub-profiles.json` (else `$XDG_CONFIG_HOME/aos/` or
`~/.config/aos/`), and only while it is the active profile.
`aos hub login --hub <origin>` makes its origin active, so when both surfaces
are Hubs without `token_credential`, sign in to a surface's origin before the
commands that reach it, or configure `token_credential` for one of them.
`AOS_TOKEN` is presented to every Hub surface that has no `token_credential`;
set it only when exactly one surface lacks one. A configured credential that
cannot be read fails the command; it never falls through to the next source.

Step commands run directly take `--token` or `AOS_TOKEN` first, then, with
`--config`, the configuration's `token_credential`, then the active login
profile. `status` and `explain` are offline and use no credential.
