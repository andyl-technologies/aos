# Secure an AOS host

AOS splits security policy between the immutable image and a machine's runtime
configuration generation. Boot-critical mechanisms such as Secure Boot,
lockdown, dm-verity, the module ABI, and image trust anchors belong in the
image. Hostname, users, SSH, firewall, audit, services, and public trust policy
can be supplied by authenticated `host.nix` and activated atomically. Start
with the server baseline, then make explicit decisions about remote access,
network exposure, audit behavior, and trust roots.

Do not treat a successful image build as evidence that a deployment meets a
particular compliance profile. The module presets configure mechanisms; the
operator still owns identity policy, key custody, logging, monitoring, and
verification on the deployed hardware.

Normal initrds fail closed without an interactive root login: the initrd root
password is locked and the upstream emergency and rescue login services are
masked. Do not introduce a shared installer or image password as a recovery
mechanism; a credential present in every public image provides no
authentication. Secure Boot plus dm-verity images instead carry two separately
signed recovery environments. Their unauthenticated interface is bounded;
access to persistent state, a maintenance shell, or restore writes requires
the per-machine off-host LUKS recovery key.

On dm-verity images, the initrd also validates the complete root identity
before systemd can generate the verity mapper or touch `/var`. The data and
hash devices must identify the same A/B slot, the root hash must be canonical,
and every scalar must occur exactly once. Alternate initrd targets, recovery
selectors, debug/break/run controls, unit injection, verity options, and their
`rd.` aliases fail into a passive target with no shell. AOS does not ship the
upstream debug or transient-command generators in its initrd.

This early validation establishes an unambiguous tuple, but PCR 12 remains the
authorization boundary for appended boot input. Until the documented PCR-12
migration is complete, do not describe the tuple guard alone as preventing an
attacker from substituting one otherwise valid A/B tuple for the other.

Recovery UKIs use the deployment db signature but deliberately omit the
normal signed PCR-11 authorization section, so entering recovery cannot
automatically unseal `/var`. The same db trust hierarchy authenticates the
copy-specific recovery UKIs, embedded slot manifest, signed release catalog,
and removable-media bundle manifest; it does not authenticate the person at
the console. The per-machine recovery key is the operator authorization
boundary. Its escrow and exercise remain deployment responsibilities.

## Start with a production baseline

`systems/server.nix` and `systems/edge.nix` define immutable roots and
boot/storage capabilities. They do not enable runtime roles on their own.
Select the appropriate role in authenticated `host.nix`:

```nix
# host.nix for a server
{
  aos.roles.server.enable = true;
  aos.security.level = "standard";
}
```

The server role enables chrony, SSH, the standard security preset, and the
package capabilities used by server deployments. The `standard` preset enables
the firewall, audit service, kernel hardening, and disables core dumps.
Resource-constrained hosts can select `aos.roles.edge.enable = true` instead;
that role enables chrony, SSH, the standard preset, and conservative runtime
memory tuning without changing the authenticated EROFS/dm-verity image root.

The available levels are:

| Level | Intended use | Current effect |
| --- | --- | --- |
| `minimal` | Narrow CI and development fixtures | Disables SELinux, audit, hardening, and firewall |
| `standard` | Normal server baseline | Enables audit, hardening, and firewall; disables core dumps |
| `hardened` | Explicit high-security policy | Currently the same module settings as `standard` |
| `debug` | Diagnostic images | Enables hardening and firewall, disables audit, permits core dumps |
| `null` | Fully manual composition | Leaves individual module defaults in control |

SELinux is not enabled by any preset today. The module exists, but a production
policy package is not wired into the presets. Do not infer SELinux enforcement
from `standard` or `hardened`.

## Restrict remote access

SSH defaults to key authentication, prohibits root password login, disables
password and keyboard-interactive authentication, and limits authentication
attempts. Keep those defaults unless the replacement authentication path has
been tested on the target image.

Prefer a named operator account:

```nix
{pkgs, ...}: {
  aos.users.groups.operator = {
    gid = 1000;
    members = ["operator"];
  };

  aos.users.users.operator = {
    uid = 1000;
    group = "operator";
    home = "/var/lib/operator";
    shell = "${pkgs.bash}/bin/bash";
    description = "Host operator";
    extraGroups = ["adm"];
  };

  aos.services.ssh = {
    enable = true;
    permitRootLogin = "no";
    passwordAuthentication = false;
    kbdInteractiveAuthentication = false;
    maxAuthTries = 3;
  };

  environment.etc."ssh/authorized_keys/operator" = {
    text = "ssh-ed25519 AAAA_REPLACE_ME operator@example.com\n";
    mode = "0600";
  };
}
```

Public SSH keys may be built into an image. Private keys must not be. Keep an
independent console or recovery path while changing access policy.

Native cloud public keys enter evaluation as typed instance facts, not as an
automatic grant. A trusted module must explicitly map those facts to an
account's authorized-keys entry; this keeps provider metadata acquisition
separate from authorization policy.

### Use OIDC-backed SSH

`opkssh` can add OIDC-backed lookup alongside the configured authorized-key
file:

```nix
{
  aos.services.opkssh = {
    enable = true;

    providers = [{
      issuer = "https://id.example.com";
      clientId = "aos-ssh";
      expirationPolicy = "12h";
    }];

    authRules = [{
      principal = "operator";
      identity = "platform@example.com";
      issuer = "https://id.example.com";
    }];

    denyUsers = ["root"];
  };
}
```

This configures `opkssh verify` as sshd's `AuthorizedKeysCommand`. Test token
issuance, issuer reachability, clock synchronization, and the denial path
before removing a static break-glass key.

## Keep the firewall closed by default

The firewall defaults to a drop policy and trusts loopback. Open only the
ports owned by services in the image:

```nix
{
  aos.firewall = {
    enable = true;
    defaultPolicy = "drop";
    forwardPolicy = "drop";
    allowedTCP = [22 443];
    allowedUDP = [];
    trustedInterfaces = ["lo"];
  };
}
```

The SSH module adds its configured port automatically. Exposed APM packages
can also contribute firewall policy through their signed activation manifest.
Inspect the evaluated firewall and the active nftables rules after every
change:

```sh
nft list ruleset
systemctl status nftables.service
journalctl -u nftables.service -b
```

Do not trust an entire workload interface merely to avoid listing ports;
`trustedInterfaces` bypasses the ordinary input filtering for that interface.

## Operate the audit trail

Audit is enabled by the server baseline. Its default rules cover process
execution, kernel modules, mounts, account files, SELinux policy, network
identity, SSH policy, privileged policy, and time changes.

Add site-specific rules without discarding the defaults:

```nix
{lib, ...}: {
  aos.security.audit.rules = lib.mkAfter [
    "-w /var/lib/acme-agent -p wa -k acme_agent_state"
  ];

  aos.security.audit.backlogLimit = 16384;
  aos.security.audit.failureMode = 1;
}
```

Failure mode `1` writes a kernel message. Mode `2` panics the host when the
audit system fails and should only be selected with a tested availability and
recovery design.

Check for rejected rules as well as service health. The rule loader logs an
individual rejection but deliberately keeps auditd running:

```sh
systemctl status auditd.service audit-rules.service
journalctl -u audit-rules.service -b
auditctl -s
auditctl -l
```

## Add organizational trust roots

AOS installs the Mozilla CA bundle by default. Append an internal root from a
tracked public certificate file:

```nix
{
  aos.security.pki.certificateFiles = [
    ./acme-root-ca.pem
  ];
}
```

The resulting bundle is installed at
`/etc/ssl/certs/ca-certificates.crt` and its common compatibility paths. A
private CA certificate is public trust material; its issuing private key is
not and must never enter the repository or Nix store.

Verify both the installed root and a real service chain:

```sh
test -r /etc/ssl/certs/ca-certificates.crt
openssl s_client \
  -connect packages.example.com:443 \
  -servername packages.example.com \
  -CAfile /etc/ssl/certs/ca-certificates.crt </dev/null
```

## Understand verified-boot status

The repository contains Secure Boot, kernel-lockdown, measured-boot, and
dm-verity variants. They exercise the implementation in fleet tests, but the
checked-in variants use `pkgs.secure-boot-test-keys`. Those keys are public and
provide no production identity.

The current Secure Boot module also requires signing-key material during the
image build. A production external-signing and key-custody workflow is not
provided as a user-facing deployment path. Do not repurpose the fixture
variants or copy their keys into a real image pipeline.

UEFI Setup Mode is an enrollment environment, not a durable operating state.
The measured-boot image temporarily formats `/var` as plaintext while Secure
Boot is not enforcing; the first enforcing boot replaces that filesystem with
the TPM-sealed volume. Do not stage configuration, packages, images, or other
state that must survive until enrollment and the first enforcing boot have
completed.

The mechanisms currently demonstrated are:

- Authenticode-signed UKIs and systemd-boot;
- optional kernel lockdown with enforced module signing and signed kexec;
- TPM2 sealing of `/var` to a signed PCR 11 policy and pinned PCR 7 and 12
  values;
- dm-verity verification of the read-only EROFS root.

Durable upgrades preserve those bindings per image generation: APM validates
the signed catalog, writes the inactive root/hash slot and slot-specific UKI,
and selects the counted entry. A boot is blessed only after the TPM reaches the
ready PCR phase, configuration has been rebound to the running image, and the
boot-commit verifier confirms the stored quote's signature, nonce, and PCR
7/11/12 values against the live TPM, with PCR 11 also checked against the
published image record. This mechanism does not supply production signing
keys, enrollment, or key custody.

The seed image gets its expected ready-phase PCR 11 from build-produced UKI
measurement metadata. That metadata is signed by the PCR-policy key and bound
to the exact UKI hash; the image references the Nix derivation outputs directly
rather than embedding store paths or captured build results in source. At boot,
AOS verifies the metadata against the public key embedded in the UKI before it
can become image-catalog authority. Registry-installed images continue to use
their independently signed release catalog.

Each committed configuration generation also carries
`gen-attestation.json`, binding its manifest to the evaluator, base library,
authenticated package-module inputs, authorized `host.nix`, normalized facts,
and the running image record's dm-verity root and expected PCR 11 value when
those are present. Measured-boot policy requires the TPM-backed generation
quote path to succeed; non-TPM variants record an explicit unquoted state
rather than pretending to have hardware evidence.
Every successful activation has a fresh `activation_id`. Reactivating the same
generation during rollback appends a new CEL event, extends PCR 15 again, and
replaces its quote, while a crash retry resumes only the retained transaction.
Inspect the current record with:

```sh
current=$(readlink -f /var/lib/profiles/system/current)
cat "$current/gen-attestation.json"
```

For a remote trust decision, use the public verifier with an enrolled quote
identity, the host CEL and quote bundle, and a policy populated from the
verifier's fleet authorization and signed image catalog. It validates the
exact embedded quote bytes, PCR
7/11/12/15, dm-verity root, authorized host-input source, signed release receipt,
active key roster, signed module/store graph, and optional independent manifest
re-derivation. See [Verify runtime attestation evidence](cli.md#verify-runtime-attestation-evidence).

Measured boot writes a generated LUKS recovery key to a configured path under
`/run` on first sealing. A production deployment must escrow that key off-host
before it disappears. Until key generation, external signing, enrollment,
escrow, rotation, and recovery are integrated and exercised together, treat
these variants as validation fixtures rather than production images.

Existing PCR-7-only enrollments are never rewritten unattended. From a clean,
signed boot, an operator supplies the off-machine recovery key to
`aos-var-policy-migrate` together with the deployment PCR public key and the
current UKI PCR signature. The tool proves the recovery key, enrolls a new
PCR-7+12 token, tests that exact token through cryptsetup's token ID, and only
then removes older TPM slots. It preserves the recovery slot throughout and
atomically writes a non-secret evidence record under `/var`.

## Verify a deployed host

After boot, capture the effective state instead of relying only on the source
configuration:

```sh
systemctl is-system-running
systemctl --failed
systemctl status sshd.service nftables.service auditd.service chronyd.service
journalctl -b -p warning
nft list ruleset
auditctl -s
cat /proc/cmdline
findmnt /
findmnt /var
```

For a release gate, add application checks, remote-access tests from the
operator network, registry TLS verification, and evidence that the expected
image and package generations are active.
