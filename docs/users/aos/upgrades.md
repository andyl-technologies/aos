# Upgrade and roll back an AOS host

An AOS system upgrade switches the immutable userspace sysroot to another
numbered generation. Package registry policy controls which sysroot is offered;
APM performs the download, activation, and generation-pointer update.

The current production-safe scope is a userspace upgrade whose kernel and UKI
are unchanged. Durable kernel/UKI replacement is not complete: the stock EFI
System Partition is read-only, while the current kernel handler still stages a
legacy boot entry. Reimage the host for a release that changes its boot
artifacts.

## Prepare the rollout

The system registry must contain a package with the same name as the installed
sysroot, normally `aos`, and its metadata must set `sysroot = true`.

Registry and channel configuration must establish rollout direction. The
upgrade resolver does not sort semantic versions or reject a downgrade; it
selects the first enabled same-name sysroot whose version string differs from
the installed version.

Before changing a host:

1. restrict it to the intended registry and channel;
2. verify the published userspace closure uses the same kernel and UKI;
3. synchronize system metadata;
4. record the current generation;
5. preview the candidate.

```sh
apm update --system
apm rollback --system --list
apm upgrade --system --dry-run
```

`apm list --installed --system` and `--upgradable --system` inspect ordinary
machine-wide runtime packages, not the OS sysroot generation.

`--dry-run` identifies the selected candidate but returns before downloading
and validating its complete closure. It is a selection check, not a substitute
for a staged rollout.

## Apply an upgrade

The unqualified command activates the userspace generation and reports whether
the kernel differs. It does not provide a durable kernel/UKI update for the
stock image:

```sh
apm upgrade --system
```

Activation modes are:

| Mode | Behavior |
| --- | --- |
| no mode flag | Activate userspace and advise when the kernel differs |
| `--live` | Invoke the incomplete legacy boot-entry handler; unsupported for durable stock-image kernel upgrades |
| `--reboot` | Activate, then request a full reboot through the incomplete kernel-update path |
| `--kexec` | Activate, then hot-load the new kernel through the incomplete kernel-update path |
| `--drain` | Drain workloads before `--reboot` or `--kexec` |

Because durable kernel handling is not ready, do not use `--reboot`, `--kexec`,
or `--live` to deploy a changed kernel in production. For a userspace-only
release, the unqualified command is the clear operating default.

System upgrade does not prompt for confirmation. Automation and runbooks should
always execute and review the dry run first.

## Verify the active generation

```sh
cat /etc/os-release
readlink /var/lib/profiles/system/current
apm rollback --system --list

systemctl is-system-running
systemctl --failed
journalctl -b -p warning
```

Verify application health in addition to systemd state. A generation switch
can complete even when a unit fails afterward.

## Interpret activation results

The activation script reports how far the transaction progressed. APM maps
those internal statuses to its ordinary success or error exit:

| Activation status | APM exit | State after the command | Operator action |
| --- | --- | --- | --- |
| `0` | `0` | New generation is live and healthy | Complete application checks |
| `5` | `0` with warning | New generation is live; stale mount cleanup failed | Inspect mounts and logs; schedule cleanup |
| `6` | `1` | New generation and `/etc` are committed; one or more units failed | Inspect failed units and roll back if service is impaired |
| `1`–`3` | `1` | Failure occurred before the `/etc` swap | Previous generation remains live; inspect the reported phase |
| `4` | `1` | `/etc` swap was incomplete | Treat state as indeterminate and recover from console |

A generic APM exit `1` does not reveal which activation phase failed. Read the
error text, then check the generation pointer and `/etc/os-release` before
taking a second action.

## Roll back

List generations and preview the target:

```sh
apm rollback --system --list
apm rollback --system --generation N --dry-run
```

Apply the selected rollback:

```sh
apm rollback --system --generation N
```

Without `--generation`, APM selects the previous generation:

```sh
apm rollback --system --dry-run
apm rollback --system
```

Rollback uses the same activation machinery and status mapping as upgrade. If
APM reports that units failed after the generation became live, an explicit
rollback is usually the safest recovery once diagnostics have been captured.

## Install a selected sysroot

For a controlled bootstrap or recovery, select the registry and sysroot package
explicitly:

```sh
apm install aos --system --registry acme --dry-run
apm install aos --system --registry acme --yes
```

This command only accepts one package marked `sysroot = true`. It is not a
machine-wide ordinary package install; those use a desired file as documented
in [Manage packages](packages.md#manage-machine-wide-packages).

## Keep scopes separate

These profiles advance independently:

```text
/var/lib/profiles/system           OS sysroot generations
/var/lib/profiles/system-packages  ordinary machine-wide package generations
/var/lib/profiles/per-user/$USER   user package generations
```

Rolling back the OS does not select an earlier user profile. Conversely, a user
package rollback does not change `/etc` or the sysroot.

There is no supported command to prune old sysroot generations today.
`apm clean --generations` operates on package profiles, and
`aos gc --list-generations` refers to an unrelated Nix profile. Keep enough
space under `/var` for the rollout and its rollback generation.
