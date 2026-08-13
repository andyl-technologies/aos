# Operate an AOS host

AOS keeps the base system immutable and puts durable runtime state under
`/var`. Routine operations therefore center on systemd, the journal, APM
profiles, the active image and configuration generations, and first-boot
provisioning evidence.

## Establish a baseline

After deployment or maintenance, capture:

```sh
cat /etc/os-release
uname -a
cat /proc/cmdline
systemctl is-system-running
systemctl --failed
findmnt /
findmnt /var
lsblk -o NAME,SIZE,FSTYPE,PARTLABEL,MOUNTPOINTS
networkctl list
apm rollback --system --list
apm rollback --system --image --list
apm list --installed --system
cat /var/lib/aos-provisioning/audit.json
```

`systemctl is-system-running` may report `degraded` because one unit failed
while the host remains reachable. Treat the failed-unit list and application
health as the decision inputs, not the aggregate word alone.

## Inspect services

Use ordinary systemd operations. The commands below use the example
`acme-agent` service from the [configuration guide](configuration.md); replace
it with a unit installed on your host:

```sh
systemctl status acme-agent.service
systemctl show acme-agent.service \
  -p ActiveState -p SubState -p Result -p ExecMainStatus
journalctl -u acme-agent.service -b
```

Before restarting a dependency, inspect reverse relationships and current
jobs:

```sh
systemctl list-dependencies --reverse acme-agent.service
systemctl list-jobs
```

An APM-managed package is grouped under an
`aos-pkg-<package>.target`. Prefer package operations over manually enabling
or deleting its generated units. A manual restart is useful for diagnosis; it
does not change the package generation or desired state.

## Read and retain logs

The journal is persistent by default under `/var/log/journal`, with a default
one-month retention window and 500 MiB maximum use. Set explicit limits in the
system variant when the host has a different storage or incident-retention
budget:

```nix
{
  aos.journald = {
    storage = "persistent";
    maxRetentionSec = "14d";
    maxUse = "1G";
    systemMaxFileSize = "100M";
    rateLimitInterval = "30s";
    rateLimitBurst = 20000;
  };
}
```

Inspect current use and warnings:

```sh
journalctl --disk-usage
journalctl -b -p warning
journalctl --list-boots
```

Forwarding to syslog only enables journald's forwarding behavior; the
deployment must also install and configure a receiver. AOS does not currently
provide a complete remote-log shipping module.

## Watch storage

The immutable root should remain read-only. Growth occurs under `/var`, package
profiles, journals, Hub state, and application state:

```sh
findmnt -no SOURCE,FSTYPE,OPTIONS /
findmnt -no SOURCE,FSTYPE,OPTIONS /var
df -h /var
du -x -h -d 2 /var | sort -h
journalctl --disk-usage
```

Do not delete APM profile directories or generation links by hand. Use
`apm clean --generations --keep N` for the invoking user's package generations,
or add `--system` to prune both machine-wide package and configuration
generations. The current generation is retained even when it falls outside the
latest-`N` window. Follow with `apm gc` to reclaim released config output and
input roots. A/B image-generation pruning is not implemented.

## Operate packages, images, and configuration generations

Preview package changes:

```sh
apm update --system
apm list --upgradable --system
apm upgrade --system --dry-run
```

`apm upgrade --system` stages an authenticated image in the inactive A/B root
slot and publishes its counted UKI as the next-boot default. It does not replace
the running root. Use the [upgrade guide](upgrades.md) for boot assessment,
image rollback, configuration rebind, and activation semantics.

`apm upgrade --system` is specifically the OS-sysroot operation. It is not a
machine-wide runtime-package upgrade. The current desired-package reconciler
can add and remove package roots but does not upgrade roots that are already
present; see [Manage packages with APM](packages.md) before designing an
application rollout.

## Monitor hardware

Hardware monitoring is opt-in:

```nix
{
  aos.monitoring.hardware = {
    enable = true;
    watchdog = true;
    watchdogTimeout = 30;
    smartd = true;
  };
}
```

The watchdog requires a working `/dev/watchdog`; validate it on the actual
platform before enabling automatic reset. `smartd` requires devices and a
controller that expose useful SMART data. Its configured mail target does not
provide a mail transport by itself, so use journal collection or another
alerting path unless mail delivery is separately configured.

```sh
systemctl status smartd.service
journalctl -u smartd.service -b
smartctl --scan-open
```

The module does not currently install a working thermal-check timer.

## Plan a maintenance window

Before changing a host:

1. verify console or out-of-band access;
2. record image, configuration, and package generations;
3. record provisioning and registry state;
4. confirm `/var` capacity and application backups;
5. run dry-run package or system selection;
6. define application health and rollback thresholds.

During the window, change one layer at a time. Do not combine a network-policy
change, registry-trust rotation, and system-generation switch unless the
recovery procedure has been tested as one transaction.

Afterward, repeat the baseline, test remote access from the operator network,
and retain the command results with the deployment record.
