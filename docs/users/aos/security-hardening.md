# Harden an AOS host

AOS security levels compose kernel, service, audit, firewall, and diagnostic
defaults. They are baselines rather than compliance certifications. Operators
remain responsible for identity policy, package selection, key custody,
monitoring, recovery, and verification on deployed hardware.

This guide covers the baseline and effective host-hardening state. Access,
network exposure, audit operation, boot integrity, and package confinement have
their own guides.

## Select a baseline explicitly

Start with the server or edge role and choose a security level in authenticated
`host.nix`:

```nix
{
  aos.roles.server.enable = true;
  aos.security.level = "standard";
}
```

The server role enables chrony, SSH, the standard security preset, and package
capabilities used by server deployments. The edge role uses the same security
baseline with conservative runtime memory tuning. Neither role enables an
application workload merely because it is present in the image.

Available levels are:

| Level | Intended use | Current effect |
| --- | --- | --- |
| `minimal` | Narrow CI and development fixtures | Disables SELinux, audit, hardening, and firewall |
| `standard` | Normal server baseline | Enables audit, kernel hardening, and firewall; disables core dumps |
| `hardened` | Explicit high-security policy | Currently the same module settings as `standard` |
| `debug` | Diagnostic images | Enables hardening and firewall, disables audit, permits core dumps |
| `null` | Fully manual composition | Leaves individual module defaults in control |

Do not advertise `hardened` as stronger than `standard` until its evaluated
policy actually differs. Do not ship `minimal` or `debug` merely to bypass a
production failure; identify the incompatible control and make an explicit,
reviewed exception.

## Understand the current MAC boundary

SELinux is not enabled by any preset. The module and package-policy machinery
exist, but the immutable root is not constructed with the complete production
labeling required for an enforcing baseline. Therefore `standard` and
`hardened` do not currently provide system-wide SELinux enforcement.

Package expose artifacts may carry generated MAC policy material, but an
operator must not infer that the host is enforcing SELinux without checking the
running kernel and policy state. Adding SELinux to a production image requires
labeled-root construction, enforcing boot tests, upgrade compatibility, and a
recovery plan.

## Keep diagnostic interfaces intentional

The standard baseline disables core dumps because process memory may contain
credentials, tokens, customer data, and cryptographic material. Enable dumps
only for a bounded diagnostic image or service with protected storage,
retention, and access policy.

Normal initrds exclude upstream debug and transient-command generators and
reject alternate initrd targets, break controls, unit injection, and ambiguous
dm-verity tuples. These are boot-integrity properties documented in [Use
Secure Boot and verify package trust](secure-boot.md), not reasons to weaken
runtime service policy.

Kernel lockdown, module signing, and signed kexec belong to Secure Boot image
policy. Confirm their effective state before claiming that a signed kernel
cannot be used to load unsigned kernel-privileged code.

## Tune hardening only with evidence

Treat a hardening exception as a privilege grant. Record:

- the exact service or workload that requires it;
- the failing operation and why a narrower interface is insufficient;
- the resulting exposure;
- the test proving the workload works with only that exception; and
- the condition for removing it.

For package services, express the grant in the signed `expose` permission
manifest so APM can compute an honest confinement label. See [Understand the
package sandbox](package-sandbox.md). For image services, keep the exception in
the owning module rather than weakening a global preset.

## Verify the deployed baseline

Capture effective state after each image or configuration transition:

```sh
systemctl is-system-running
systemctl --failed
systemctl status sshd.service nftables.service auditd.service chronyd.service
journalctl -b -p warning
cat /proc/cmdline
cat /sys/kernel/security/lockdown 2>/dev/null
findmnt /
findmnt /var
```

Then run the checks owned by the relevant guides:

- [Configure networking](networking.md) for routes, listeners, and firewall
  rules;
- [Control access to an AOS host](access-control.md) for accounts and SSH;
- [Audit an AOS host](auditing.md) for audit state and loaded rules;
- [Use Secure Boot and verify package trust](secure-boot.md) for verified boot;
- [Configure package registries](registries.md) for effective trust policy; and
- [Understand the package sandbox](package-sandbox.md) for workload privileges.

A passing systemd state is necessary but not sufficient. Add application
health, remote-access, registry, storage, attestation, and recovery checks for
the deployment's actual threat and availability model.
