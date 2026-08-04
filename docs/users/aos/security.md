# Secure an AOS host

AOS security policy is currently built into the published system image. Start
with the server baseline, then make explicit decisions about remote access,
network exposure, audit behavior, and trust roots.

General runtime `host.nix` activation is not complete. Users of the current
golden image cannot change these module settings at runtime; release
maintainers must apply them while producing the image. The examples below
document the policy and its current effect. See
[Build and customize release images](../../maintainers/system-images.md) for
the source-build workflow.

Do not treat a successful image build as evidence that a deployment meets a
particular compliance profile. The module presets configure mechanisms; the
operator still owns identity policy, key custody, logging, monitoring, and
verification on the deployed hardware.

## Start with a production baseline

`systems/server.nix` defines the immutable root and boot/storage capability. It
does not enable the server runtime role on its own. A deployment variant should
enable that role explicitly:

```nix
# systems/acme-server.nix
{...}: {
  imports = [./server.nix];

  aos.roles.server.enable = true;
  aos.security.level = "standard";
}
```

The server role enables chrony, SSH, the standard security preset, and the
package capabilities used by server deployments. The `standard` preset enables
the firewall, audit service, kernel hardening, and disables core dumps.

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

The mechanisms currently demonstrated are:

- Authenticode-signed UKIs and systemd-boot;
- optional kernel lockdown with enforced module signing and signed kexec;
- TPM2 sealing of `/var` to a signed PCR 11 policy and pinned PCR 7 value;
- dm-verity verification of the read-only EROFS root.

Measured boot writes a generated LUKS recovery key to a configured path under
`/run` on first sealing. A production deployment must escrow that key off-host
before it disappears. Until key generation, external signing, enrollment,
escrow, rotation, and recovery are integrated and exercised together, treat
these variants as validation fixtures rather than production images.

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
