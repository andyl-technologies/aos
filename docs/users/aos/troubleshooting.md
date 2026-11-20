# Troubleshoot an AOS host

AOS does not have a single host-status command. Start with systemd state, the
active generation, and the current boot journal, then narrow the search to
provisioning or APM.

## Collect a baseline

```sh
cat /etc/os-release
readlink /var/lib/profiles/system/current
cat /var/lib/profiles/image/state.json
cat /var/lib/profiles/system/state.json
apm config rollback --list

systemctl is-system-running
systemctl --failed
systemctl list-jobs
journalctl -b -p warning
```

Journald persists logs under `/var/log/journal`. Use `journalctl -b -1` for the
previous boot and `journalctl -b -u UNIT` for one unit.

## The machine does not finish first boot

First boot must authorize and evaluate storage intent before it changes the
disk. The initrd controller executes the checked stage plan; metadata and
storage steps are package-owned provider operations rather than separate
systemd services. Inspect the serial or physical console and the controller:

```sh
systemctl status aos-ability-initrd-controller.service
journalctl -b -u aos-ability-initrd-controller.service
```

The controller journal names the failing checked operation and selected
provider. Use that identity with the package's generated `apm docs` or Hub
documentation to inspect its consumed and exposed abilities.

Common causes are:

- the target has less trailing space than the requested swap and `/var`
  minimum;
- a raw disk was enlarged without moving its backup GPT header;
- metadata has the wrong filesystem label or payload path;
- user-data contains JSON, YAML, or cloud-config instead of literal Nix;
- signed mode has no matching image-baked key or detached signature;
- an explicitly named `/dev/disk/by-id/...` device is absent;
- the requested storage plan conflicts with an already committed plan.

Check the current transient state when a recovery shell is available:

```sh
cat /run/aos/storage-provisioning/provisioning-plan.json
find /run/aos/storage-provisioning/repart.d -maxdepth 3 -type f -print
```

`divergent` means the host already committed a different storage plan. Reimage
the host after preserving persistent data. A pending provisioning marker means
an earlier mutation was interrupted; AOS refuses automatic replay and has no
public recovery command for that state.

## Metadata was accepted but activation did not complete

Stage 2, the host stage that runs after the initrd hands off, selects
packages, evaluates the complete configuration, and executes its effects. Check
the units that carry it and the committed result:

```sh
apm config status
systemctl status aos-ability-host-receiver.service \
  aos-ability-host-controller.service
journalctl -b \
  -u aos-ability-host-receiver.service \
  -u aos-registry-sync.service \
  -u aos-ability-host-controller.service \
  -u aos-activate.service
readlink /var/lib/profiles/system/current
systemctl --failed
```

`aos-registry-sync.service` and `aos-activate.service` exist on images that
enable the host configuration control plane; `journalctl` ignores a unit that
is absent.

A complete transaction must:

1. verify the committed initrd handoff;
2. select the desired packages and acquire missing ones through the configured
   signed registries;
3. evaluate the complete native graph;
4. execute its effects in dependency order, including the EROFS `/etc` lower;
   and
5. publish the system profile's `current` pointer.

The journal names the step that failed. If no new `current` pointer was
published, the previous configuration remains live, and pending work is
recovered before another change is accepted. A published pointer does not prove
that every service is healthy: check failed units and application health too.
[Inspect configuration state](configuration.md#inspect-configuration-state)
lists the retained evaluation inputs and journals.

Storage is the exception: it is projected and committed in the initrd before
stage 2 starts. See the [`host.nix` guide](host-nix.md) for the exact
lifecycle.

## SSH is unreachable

From the console:

```sh
systemctl status sshd.service
journalctl -b -u sshd.service
cat /etc/ssh/sshd_config
ls -l /etc/ssh/authorized_keys
```

Confirm that:

- authenticated `host.nix` enables SSH directly or selects
  `aos.roles.server`/`aos.roles.edge`;
- the active configuration generation contains the expected
  `/etc/ssh/authorized_keys/USER`;
- the firewall admits the SSH port (the SSH module contributes its configured
  port; other ports need `aos.networkPolicy.allowedTCP`);
- the network interface name and address match the target;
- the hypervisor or cloud security policy also allows the port.

Cloud metadata public keys are available to evaluation as the typed
`host.facts.ssh_authorized_keys` input. They are not implicitly trusted as an
account policy: verify that a trusted module deliberately projected them to the
expected user's authorized-keys file. Presence in instance metadata alone is
not proof that login is configured.

## A package is installed but its command is missing

Login sessions put the account's package profile and then the machine-wide
profile on `PATH`. A shell started before the package was installed, or one
that replaced `PATH`, may not see the command. Stock images also do not
provision unprivileged writable user profiles; this procedure assumes the
operator has created the account's XDG and profile storage. Inspect the profile
and invoke the binary directly:

```sh
apm list --installed
apm files PACKAGE
echo "$PATH"
/var/lib/profiles/per-user/$USER/current/bin/COMMAND --version
```

If the direct path works, log in again. For a machine-wide package, add
`--system` to the `apm` commands and look under
`/var/lib/profiles/system/current/bin` instead.

If the package is not in the profile, synchronize metadata and preview a
reinstall rather than editing profile symlinks by hand.

## APM cannot verify a registry

Inspect policy and configuration before bypassing verification:

```sh
apm policy PACKAGE --system
apm registry --system list
apm update --system --registry NAME
```

These commands inspect the system scope. Omit `--system` only when diagnosing
an account with a separately provisioned writable user registry and package
profile.

Registry seeds are under `/etc/apm`; persistent machine-wide overrides and
trust pins are under `/var/lib/apm`. User overrides are under `~/.config/apm`.
Check for a higher-precedence user entry pointing at a different URL or key.

Do not use `--no-verify` to make a production incident disappear. Confirm the
registry key through an independent channel and correct the trust configuration.

## A system upgrade returned nonzero

First determine whether the generation switched:

```sh
readlink /var/lib/profiles/system/current
cat /etc/os-release
systemctl --failed
```

Follow the direct error first. Resolution, download, verification, or image
import can fail before the inactive slot is changed. Once staged, the running
image remains unchanged until reboot; inspect `pending`, `default`, and
`running` in `/var/lib/profiles/image/state.json`. After boot, configuration
re-evaluation or activation can fail before the image is blessed, allowing
sd-boot boot counting to fall back. The full status and rollback procedure is in
[Upgrade and roll back a host](upgrades.md#interpret-configuration-activation-results).

Capture the current boot journal before rollback:

```sh
journalctl -b > /var/tmp/aos-upgrade-failure.log
apm config rollback --list
apm config rollback --generation N --dry-run
```

## `/var` is filling up

Identify the consumer before removing anything:

```sh
df -h /var
du -x -h -d 2 /var | sort -h
```

Relevant persistent trees include:

```text
/var/lib/profiles/image
/var/lib/profiles/system
/var/lib/profiles/per-user
/var/lib/apm
/var/lib/aos-provisioning
/var/log/journal
```

Do not delete profile generations or provisioning state by hand. Prune package
and configuration generations with `apm clean` and `apm gc` as described in
[Clean up old packages](packages.md#clean-up-old-packages). There is no
supported A/B image-generation prune command, so preserve image rollback
capacity and expand or reimage the host if the image profile is the material
consumer.

## Report an issue

Include the system version, active generation, exact command and exit status,
failed units, and relevant journal section. Redact registry credentials,
metadata payloads, host facts, and service secrets before sharing logs.
