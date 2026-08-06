# Upgrade and roll back an AOS host

AOS records two independent generation axes:

- an image generation owns an A/B root slot, UKI, kernel, initrd, base module
  library, evaluator, and expected measurements;
- a configuration generation owns the evaluated manifest, retained inputs,
  package projection, and EROFS `/etc` lower activated on the running image.

Image state is under `/var/lib/profiles/image`; configuration state is under
`/var/lib/profiles/system`. Advancing one axis does not silently rewrite the
other.

## Prepare the rollout

The system registry must contain one package with the same name as the running
sysroot, normally `aos`, with `sysroot = true`. Its signed metadata must publish
the raw OTA payload, both slot-specific UKIs, module ABI, and the root-hash,
expected-measurement, and Secure Boot facts required by the target policy.

Registry and channel policy establishes rollout direction. The upgrade
resolver selects the first enabled same-name sysroot whose version differs
from the running image; it does not infer semantic-version ordering.

Before changing a host:

1. restrict it to the intended registry and channel;
2. verify the image, UKIs, root hashes, and expected measurements in the signed
   catalog;
3. synchronize system metadata;
4. record both generation axes and the running slot;
5. preview the candidate.

```sh
apm update --system
apm rollback --system --image --list
apm rollback --system --list
apm upgrade --system --dry-run
```

The dry run resolves the selected candidate and reports the plan without
downloading, writing a root slot, changing the boot default, or activating
configuration. Use `apm switch --dry-run` as documented in the
[configuration guide](configuration.md) to preview a
`host.nix` configuration transaction, including `/etc`, unit, closure, and
provider-resolution changes.

## Stage an A/B image upgrade

```sh
apm upgrade --system
```

APM verifies the registry graph and Secure Boot policy, imports the
authenticated OTA payload, copies the currently needed evaluator closure to
the persistent store overlay, writes the inactive root and, for a verity image,
its hash slot, publishes its UKI last, and makes the counted UKI the durable
next-boot default. The running image and active configuration are unchanged
until reboot.

Activation modes are:

| Mode | Behavior |
| --- | --- |
| no mode flag | Stage the inactive slot and print a reboot advisory |
| `--live` | Stage only; like the default, defer the image transition until reboot |
| `--reboot` | Stage, then request a full reboot |
| `--kexec` | Rejected for A/B images because kexec cannot change the root slot |
| `--drain` | Drain workloads before a requested `--reboot` |

The candidate UKI carries an sd-boot boot-counting suffix. Each unsuccessful
attempt decrements its counter; exhaustion demotes the candidate and falls back
to the other slot. A candidate is blessed only after it boots, re-evaluates the
host configuration against its own ABI-pinned base library, commits a matching
configuration generation, reaches the TPM ready phase, and passes local
verification of the generation quote against the live PCR 7/11 values and the
published image PCR 11. A failed ready transition leaves evaluation and boot
blessing inactive.

## Verify an image transition

After reboot:

```sh
cat /proc/cmdline
cat /etc/os-release
cat /var/lib/profiles/image/state.json
cat /var/lib/profiles/system/state.json
readlink /var/lib/profiles/system/current
cat /run/aos/activation.json

systemctl is-system-running
systemctl --failed
journalctl -b -p warning
```

Confirm that `running` names the expected image, `pending` has been cleared,
the current configuration's `image_gen_parent` matches it, and the activation
record describes the same committed transaction. Verify application health in
addition to systemd state.

## Roll back configuration

List configuration generations and preview a target:

```sh
apm rollback --system --list
apm rollback --system --generation N --dry-run
```

Apply it:

```sh
apm rollback --system --generation N
```

Without `--generation`, APM chooses the most recent earlier configuration.
When its module ABI matches the running image, rollback validates the retained
manifest and switches directly. Across an ABI boundary, direct activation is
refused: APM re-evaluates the retained `host.nix`, instance facts, and exact
authenticated package module inputs against the running image, then commits a
new compatible configuration generation. This replay requires no registry
round trip because each generation retains its `cfgsrc` inputs.

## Roll back the image

List and preview the image axis separately:

```sh
apm rollback --system --image --list
apm rollback --system --image --generation N --dry-run
```

Select the older image as the durable next boot, optionally rebooting in the
same operation:

```sh
apm rollback --system --image --generation N
apm rollback --system --image --generation N --reboot
```

The running kernel does not change until reboot. On the selected image's first
boot, AOS re-evaluates the authoritative metadata input, or its hash-checked
last-known-good copy, against that image's base library. It commits the rebound
configuration before making the image the durable successful default.

## Interpret configuration activation results

The activation script publishes a transaction-bound record after the pointer
and `/etc` swap. Its `activation_exit` field has this meaning; the outer `apm`
command can still report a generic failure from graph orchestration:

| `activation_exit` | State after the command | Operator action |
| --- | --- | --- |
| `0` | New generation is live and healthy | Complete application checks |
| `5` | New generation is live; stale mount cleanup warned | Inspect mounts and schedule cleanup |
| `6` | New generation is committed but one or more units failed | Inspect failed units; roll back configuration if service is impaired |
| `1`-`3` | Failure occurred before the `/etc` swap | Previous generation remains live; inspect the reported phase |
| `4` | `/etc` swap or post-swap evidence is indeterminate | Use console access and the recovery procedure |

Graph recovery does not treat a degraded or stale activation record as a
completed transaction. Re-running the same transaction retries its package
and activation work rather than silently skipping it.

## Install a selected sysroot

For controlled staging, select the registry and sysroot package explicitly:

```sh
apm install aos --system --registry acme --dry-run
apm install aos --system --registry acme --yes
```

This accepts exactly one package marked `sysroot = true` and stages its A/B
image. Ordinary machine-wide packages use a desired file as documented in
[Manage packages](packages.md#manage-machine-wide-packages).

## Keep scopes separate

```text
/var/lib/profiles/image             A/B image generations
/var/lib/profiles/system            configuration generations
/var/lib/profiles/system-packages   ordinary machine-wide package generations
/var/lib/profiles/per-user/$USER    user package generations
```

Rolling back an image does not pick an arbitrary old configuration; boot-time
re-evaluation establishes a compatible one. Conversely, configuration or user
package rollback does not replace the running kernel or root slot.

`apm clean --generations --keep N` prunes the invoking user's package profile.
Add `--system` to prune both ordinary machine-wide package generations and
configuration generations, keeping the latest `N` of each plus each profile's
current generation. Configuration pruning is serialized with activation and
releases its `cfg/` and `cfgsrc/` roots; a later `apm gc` can reclaim the now
unreachable store paths. A/B image-generation pruning remains unavailable.
`aos gc --list-generations` refers to an unrelated Nix profile.
