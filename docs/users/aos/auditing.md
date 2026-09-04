# Audit an AOS host

The AOS audit service records security-relevant kernel and userspace activity.
The server baseline enables it with rules for process execution, kernel
modules, mounts, account files, SELinux policy, network identity, SSH policy,
privileged policy, and time changes.

Audit records support investigation and monitoring. They do not prevent an
operation, establish package authenticity, or replace application logs.

## Extend the default rules

Append site-specific rules without discarding the baseline:

```nix
{lib, ...}: {
  aos.security.audit.rules = lib.mkAfter [
    "-w /var/lib/acme-agent -p wa -k acme_agent_state"
  ];

  aos.security.audit.backlogLimit = 16384;
  aos.security.audit.failureMode = 1;
}
```

Use stable keys such as `acme_agent_state` so monitoring and incident queries
do not depend on the rule's display order. Avoid broad directory watches whose
volume can exhaust the backlog or hide the event of interest.

## Choose the failure mode deliberately

Failure mode `1` writes a kernel message when the audit subsystem cannot record
an event. Failure mode `2` panics the host. Select mode `2` only when the
deployment has explicitly chosen integrity over availability and has tested
reboot, failover, recovery, and alert delivery under audit exhaustion.

Backlog sizing must account for boot bursts, package activation, workload
start, and incident conditions. A larger number defers overflow; it does not
repair an event pipeline that cannot drain.

## Verify service and rule state

Check rejected rules as well as service health. The rule loader can report an
individual rejection while leaving auditd running:

```sh
systemctl status auditd.service audit-rules.service
journalctl -u audit-rules.service -b
auditctl -s
auditctl -l
```

Confirm that:

- audit is enabled and not unexpectedly immutable or disabled;
- the backlog and failure mode match policy;
- every required rule is present;
- no rule failed to parse or resolve its path; and
- records reach the intended retention or forwarding system.

Run these checks after image updates and configuration activations. A source
configuration is not evidence that the kernel accepted the resulting rule set.

## Query events by purpose

Use rule keys and bounded time ranges when investigating:

```sh
ausearch -k acme_agent_state -ts boot
ausearch -m USER_AUTH,USER_LOGIN -ts today
ausearch -m KERNEL_MODULE -ts boot
```

Correlate audit timestamps with the system journal, APM generation state,
package CEL events, Hub audit records, and external identity-provider logs.
Preserve original records before performing repairs that may change ownership,
mounts, packages, or accounts.

## Protect and retain audit data

Audit records stored only on the affected host may be unavailable after disk
failure or hostile root access. Define retention, forwarding, access, clock,
and privacy policy for the deployment. Treat forwarding credentials as secrets
and use the narrow service credential interfaces described in [Manage secrets
on AOS](secrets.md).

Audit rules may capture identifiers and paths that are operationally or
personally sensitive. Collect the minimum useful data, protect it in transit
and at rest, and set an explicit deletion policy.

## Know the boundary

Audit service health does not prove that:

- Secure Boot or dm-verity is enforcing;
- a package came from a trusted registry;
- an exposed service retained its sandbox;
- a remote collector received every record; or
- an attacker with kernel authority could not interfere.

Use [security hardening](security-hardening.md), [Secure Boot](secure-boot.md),
[registry verification](registries.md), and [package confinement](package-sandbox.md)
as separate controls.
