# Manage secrets on AOS

Nix expressions and build inputs are not secret-delivery mechanisms. Values
embedded in a derivation, generated file, systemd unit, image, or command line
can appear in the Nix store, build logs, process listings, image layers, or Git
history.

Use AOS configuration for public policy and trust anchors. Deliver private
material through an external system into writable runtime state.

## Classify the material

These values are normally safe to keep in a deployment repository:

- public SSH keys;
- public CA certificates;
- registry and host-configuration verification keys;
- OIDC issuer URLs and client IDs;
- service endpoints and non-secret policy.

These values are secrets:

- SSH, TLS, registry, Secure Boot, and cache-signing private keys;
- OIDC client secrets;
- passwords and provisioning tokens;
- cloud and object-storage credentials;
- Hub sealing and JWT keys;
- disk-encryption recovery keys.

A detached signature proves integrity and signer authorization. It does not
encrypt `host.nix`, registry metadata, or any value placed beside the
signature.

## Keep secrets out of builds

Do not write secrets directly into module values:

```nix
{
  # Wrong: this value becomes part of the evaluated system and image.
  systemd.services.acme-agent.environment.API_TOKEN = "secret-value";
}
```

Do not reference a private file as a Nix path and assume it remains external.
Nix can copy path inputs into the store. Do not pass a secret as an ordinary
builder environment value; derivation metadata and logs are not a secret
boundary.

Instead, configure the service to read a runtime file whose contents are not
created by Nix:

```nix
{
  systemd.services.acme-agent = {
    description = "Acme agent";
    wantedBy = ["multi-user.target"];
    after = ["network-online.target"];
    wants = ["network-online.target"];

    serviceConfig = {
      Type = "simple";
      ExecStart = "/var/lib/acme-agent/bin/acme-agent";
      EnvironmentFile = "/var/lib/acme-agent/credentials.env";
      User = "acme-agent";
      Group = "acme-agent";
      ProtectSystem = "strict";
      ProtectHome = true;
      NoNewPrivileges = true;
      ReadWritePaths = "/var/lib/acme-agent";
    };
  };
}
```

The example assumes the application and its credentials are provisioned under
`/var/lib/acme-agent`; it does not create either one. A packaged application
would normally use its immutable store path for `ExecStart` and only keep the
credential in `/var`. Provision `credentials.env` through the deployment's
external secret system before starting the service. Set restrictive ownership
and mode, and ensure the service sandbox can read only the required path.

Runtime configuration activation supports an opaque `secretRef` boundary. A
reference contains a systemd credential name, writable credstore destination,
encryption policy, consuming units, and resolver handle. There is no plaintext
`value` or `text` field, and unknown fields fail validation, so secret bytes
cannot enter the evaluated manifest.

Activation validates every reference against the package's signed credential
declaration before consumer reconciliation. Desired-state and system-credential
references obtain bytes outside evaluation, optionally encrypt them to the
configured signed-PCR policy, and stage mode-`0600` credstore files without
placing plaintext in a retained generation. A TPM2-credstore reference instead
verifies a package-authored sealed artifact in the fully composed staged view
before any live unit is stopped; it does not fetch plaintext or reseal it. When
an authenticated reference disappears, activation removes only the source
recorded in the prior retained manifest, in the same rollback-capable
transaction as replacements. Credential-triggered restarts are deduplicated,
dependency ordered, and limited to consumers that were active before
publication. Every selected consumer is attempted even if an earlier job
fails. A missing value, unsafe path, unavailable encryption policy, or
unsupported resolver fails closed before those restarts.
After the atomic `/etc` swap, activation pauses before any consumer starts,
publishes the complete credential set under a durable transaction journal, and
folds changed consumers into the existing unit-reconciliation plan. A later
publication failure restores every earlier target and enters rescue without
publishing the generation pointer or activation proof. Boot recovery resolves
an interrupted prepared or committed journal before the retained configuration
lower and its consumers are admitted.

The implemented sources are:

- a package-authored TPM2-sealed credstore artifact;
- a reviewed desired-state credential supplied outside evaluation;
- a platform/systemd credential under `/run/credentials/@system`.

`host.nix` carries only the handle and policy. It must never contain the bytes:

```nix
{
  aos.apm.installAtBoot.credentials.web.api-token = {
    source = "/etc/credstore.encrypted/web/api-token";
    encrypted = true;
    units = ["web.service"];
    ref = "system-credential:bootstrap-token";
  };
}
```

This assumes the signed `web` package exposes the matching `api-token`
credential and the deployment platform supplies `bootstrap-token` through the
systemd credential channel. AOS does not ship a general Vault or cloud secret
manager backend; those remain external delivery systems. Do not place secret
bytes in metadata or `host.nix` while attempting to use a reference.

## Avoid secret command-line arguments

Prefer stdin, a protected file, or a secret-manager lookup. For example, Hub
initialization accepts a password over stdin:

```sh
printf '%s\n' "$ROOT_PASSWORD" | \
  aos-hub --root /var/lib/aos-hub init \
    --root-email ops@example.com \
    --root-password-stdin
```

APR can store a command that retrieves a registry signing key:

```sh
apr keys register release \
  --registry acme \
  --key-command 'secret-tool lookup service aos-registry key release'
```

The stored command must contain only lookup metadata. Its standard output must
contain only the OpenSSH private key. Review the shell command as executable
configuration and restrict who can modify the registry's local configuration.

## Manage service credentials

For every runtime credential, define:

1. the system of record;
2. the delivery identity and authenticated channel;
3. the on-host path, owner, group, and mode;
4. whether a service reload or restart consumes a new value;
5. rotation overlap and revocation behavior;
6. backup and recovery policy;
7. the logs and alerts that show delivery failure.

Use a dedicated file per trust boundary. Avoid one environment file shared by
unrelated services. Environment variables are inherited by child processes
and may be exposed by diagnostics; use a file descriptor or service-specific
file when the application supports it.

Persistent secrets belong under a protected directory in `/var`, not the
immutable root. Ephemeral credentials may live under `/run` and must be
reissued after boot. Do not place the only recovery key on the encrypted volume
it unlocks.

## Operate AOS Hub keys

A native AOS Hub stores `secret.key` in its state root with mode `0600`. It
seals stored OIDC secrets, storage credentials, and hosted signing-key
material. Back it up at the same recovery point as `hub.db` and bound storage.
Losing it makes sealed values unusable.

When `AOS_HUB_SECRET_KEY_FILE` points outside the state root, the external file
must be included in the same backup and restore procedure.

The Cloudflare deployment uses two distinct secrets:

- `HUB_JWT_SECRET` signs access tokens; rotation invalidates issued JWTs;
- `HUB_SEAL_KEY` protects stored credentials and signing material; replacing it
  without migration can make sealed data unreadable.

Routine Worker deployment preserves existing values when secret flags are
omitted. Record initially generated values in the organization's secret store
before considering the installation complete.

## Rotate safely

A rotation plan should be reversible until every dependent has moved:

1. create the replacement secret in the system of record;
2. distribute it without removing the old value where overlap is supported;
3. reload or restart a canary consumer;
4. verify authentication and application behavior;
5. move the remaining consumers;
6. revoke the old credential;
7. verify that use of the old credential fails;
8. remove obsolete on-host copies and update recovery material.

Not every key supports overlap. Registry trust rotation requires a signed
transition release; Hub sealing-key rotation requires migration of sealed
values; disk recovery keys require tested enrollment and removal commands.
Follow the subsystem-specific runbook instead of applying a generic file
replacement.

## Respond to exposure

If a secret enters Git, a Nix expression, a derivation, or an image, assume it
has been copied. Removing the line in a later commit does not revoke the value
or remove existing store and image copies.

Revoke or rotate the credential first. Then identify builds, images, caches,
logs, and hosts containing it; remove those artifacts according to retention
policy; and record the affected scope. For a registry signing-key incident,
use [Manage registry trust and incidents](../registry/trust.md).
