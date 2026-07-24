# Golden image and `host.nix` boundary

AOS consumers are not expected to fork or rebuild the base image to configure
a machine. The release image is a capability and trust substrate. The
authenticated `host.nix` delivered in cloud user-data is the primary
configuration mechanism.

## Classification rule

An input belongs in the image only when at least one of these is true:

1. it is required to obtain or authenticate `host.nix`;
2. it changes the signed/measured boot artifact;
3. it selects code or a driver that must exist before host evaluation;
4. changing it requires a different kernel, initrd, immutable root, or module
   schema ABI;
5. accepting it from `host.nix` would create a circular trust decision.

Everything else is host policy and must be expressible through `host.nix`.

## Image-owned capabilities

- kernel, kernel configuration, firmware, and initrd driver closure;
- systemd-stub/sd-boot, UKI command line, Secure Boot signing, lockdown, and
  module-signing enforcement;
- measured-boot PCR policy, dm-verity root and roothash binding;
- ESP/root image layout and A/B image mechanics;
- base module library, evaluator, module ABI, and activation machinery;
- metadata discovery, minimal DHCP/config-drive support, and facts acquisition;
- restricted provisioning evaluator, repart/format/encryption tools, and
  recovery behavior;
- initial host-configuration and package-registry verification roots;
- the minimal package set needed to boot, evaluate, fetch, verify, activate,
  roll back, and diagnose a failed configuration.

These are release engineering inputs. A normal host configuration cannot
change them until a new signed image is installed.

## `host.nix`-owned policy

- `aos.provisioning.storage`;
- server/edge/workload role selection;
- desired APM packages and package configuration;
- hostname, locale, timezone, and persistent host state version;
- network interfaces, addresses, VLANs, bonds, routes, DNS, and MTU;
- users, groups, SSH keys, and authentication policy;
- SSH, chrony, registry-hub, monitoring, and workload services;
- firewall policy, audit rules, runtime sysctls, core-dump policy, and selected
  packaged SELinux/eBPF policy;
- journald retention and forwarding;
- PAM rules and resource limits;
- runtime CA certificates, registry routing/priority, and package selection;
- ordinary `/etc` files, systemd units, mounts, and credentials by reference.

The base module schemas still ship in the image. Moving policy to `host.nix`
means the operator selects their values at runtime; it does not move the
implementation code out of the base library.

## Split mixed profiles

Profiles that currently mix image mechanics and runtime policy must be split.
For example, the current server profile combines immutable erofs-root choices
with SSH, chrony, users, security level, and package declarations.

The target shape is:

```text
release image capability module
  immutable root + boot/initrd requirements

host role module
  runtime defaults for SSH, time, security, and desired packages
```

The role module is bundled in the base library and selected from `host.nix`,
for example:

```nix
{
  aos.roles.server.enable = true;
}
```

Production images never enable a debug role or passwordless console autologin.
An initrd recovery shell, when intentionally shipped, remains an image
capability because `host.nix` cannot alter the initrd already executing.

## Package policy

Operators select packages by authenticated registry name, not by Nix
derivation:

```nix
{
  aos.apm.desiredPackages = [
    "k3s-worker"
    "node-exporter"
  ];
}
```

Package config modules contribute their users, D-Bus policy, units, and files
only after the package is in the resolved desired set. Workload accounts such
as a registry-server service user do not belong in a universal server image.

Image bundling is reserved for bootstrap/recovery packages and deliberate
offline installations. Bundling and enabling are separate decisions.

## Trust bootstrap

`host.nix` cannot establish the key that authenticates itself. A universal
golden image carries a stable vendor/fleet root and may accept an operator key
through a signed delegation chain delivered beside `host.nix`. Similarly, the
image carries an initial package-registry verification root while `host.nix`
may select URLs, mirrors, and priorities bound to an admitted registry
identity.

Runtime private CAs may be declared as configuration data and assembled by the
manifest materializer. A CA required to fetch or authenticate `host.nix`
itself is bootstrap trust and remains image-owned.

Secrets never appear as plaintext Nix values. `host.nix` carries credential
handles; activation resolves them from the secret transport after
authentication.

## Eliminate artificial image-fixed artifacts

On-host evaluation cannot run derivation builders. That restriction must not
turn host policy into image policy. Config-dependent outputs are rendered as
manifest data or assembled by a bounded runtime materializer:

- PAM limits become generated `/etc` text;
- extra CA certificates become manifest inputs to the runtime CA bundle;
- systemd job scripts are carried as text and materialized per generation;
- package-owned D-Bus policy is assembled from the resolved package set;
- desired-package profiles and presets are generated from `host.nix`.

Only artifacts that are truly functions of the immutable image may use the
frozen-artifact channel.

## Base behavior when configuration fails

The universal image must remain safe and diagnosable with absent or invalid
configuration:

- first-boot storage uses the default provisioning module only when
  `host.nix` is absent, never when a present file fails authentication/eval;
- no workload role or debug login is enabled;
- bootstrap networking is sufficient to retry metadata and registry access;
- the last committed configuration generation remains active;
- a failed stage-2 evaluation does not partially activate;
- a failed uncommitted provisioning boot blocks disk-dependent startup with a
  clear console diagnostic.
