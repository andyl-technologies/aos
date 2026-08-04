# Troubleshoot an AOS host

AOS does not have a single host-status command. Start with systemd state, the
active generation, and the current boot journal, then narrow the search to
provisioning or APM.

## Collect a baseline

```sh
cat /etc/os-release
readlink /var/lib/profiles/system/current
apm rollback --system --list

systemctl is-system-running
systemctl --failed
systemctl list-jobs
journalctl -b -p warning
```

Journald persists logs under `/var/log/journal`. Use `journalctl -b -1` for the
previous boot and `journalctl -b -u UNIT` for one unit.

## The machine does not finish first boot

First boot must authorize and evaluate storage intent before it changes the
disk. Inspect the serial or physical console and these units:

```sh
systemctl status \
  aos-metadata-detect.service \
  aos-metadata-fetch.service \
  aos-metadata-authorize.service \
  aos-provisioning-eval.service \
  aos-repart.service

journalctl -b \
  -u aos-metadata-detect.service \
  -u aos-metadata-fetch.service \
  -u aos-metadata-authorize.service \
  -u aos-provisioning-eval.service \
  -u aos-repart.service
```

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
cat /run/aos-metadata/platform.env
cat /run/aos-metadata/provisioning-plan.json

if test -r /run/aos-metadata/storage-coherence; then
  cat /run/aos-metadata/storage-coherence
else
  echo "storage coherence was not evaluated this boot"
fi
```

`divergent` means the host already committed a different storage plan. Reimage
the host after preserving persistent data. A pending provisioning marker means
an earlier mutation was interrupted; AOS refuses automatic replay and has no
public recovery command for that state.

## Metadata was accepted but settings did not change

Check full evaluation:

```sh
systemctl status aos-eval.service
journalctl -b -u aos-eval.service
test -s /run/aos/manifest.json
```

Boot-time evaluation alone does not immediately apply general host fields.
Hostname, networking, users, SSH keys, and services may appear in a valid
manifest without changing the live host. A later sysroot generation switch can
materialize that manifest into the candidate `/etc`, and package graph
compilation can act on its package set. Bake required boot policy into a system
variant as described in [Customize AOS](configuration.md), and review the
manifest before a later generation activation.

Storage is the exception: it is projected and committed in the initrd before
the full manifest exists. See the [`host.nix` guide](host-nix.md) for the exact
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

- the image variant enables SSH;
- the expected public key is baked into
  `/etc/ssh/authorized_keys/USER`;
- the SSH port is open in `aos.firewall.allowedTCP`;
- the network interface name and address match the target;
- the hypervisor or cloud security policy also allows the port.

Cloud metadata keys are not installed by the current runtime activation path.
Do not treat their presence in instance metadata as proof that login is
configured.

## A package is installed but its command is missing

User package executables are not added to the default `PATH`. Stock images also
do not provision unprivileged writable user profiles; this procedure assumes
the operator has created the account's XDG and profile storage. Inspect the
profile and invoke the binary directly:

```sh
apm list --installed
apm files PACKAGE
/var/lib/profiles/per-user/$USER/current/bin/COMMAND --version
```

For the current shell:

```sh
export PATH="/var/lib/profiles/per-user/$USER/current/bin:$PATH"
```

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

Follow the direct error first. Resolution, download, verification, or import
can fail before activation, and changed-kernel or reboot handling can fail after
the generation commit. When the activation script reports a phase, its message
distinguishes a pre-swap failure, an incomplete `/etc` swap, and a
live-but-degraded generation; stale mount cleanup is a warning on an otherwise
successful command. The full status mapping and rollback procedure are in
[Upgrade and roll back a host](upgrades.md#interpret-activation-results).

Capture the current boot journal before rollback:

```sh
journalctl -b > /var/tmp/aos-upgrade-failure.log
apm rollback --system --list
apm rollback --system --generation N --dry-run
```

## `/var` is filling up

Identify the consumer before removing anything:

```sh
df -h /var
du -x -h -d 2 /var | sort -h
```

Relevant persistent trees include:

```text
/var/lib/profiles/system
/var/lib/profiles/system-packages
/var/lib/profiles/per-user
/var/lib/apm
/var/lib/aos-provisioning
/var/log/journal
```

Do not delete profile generations or provisioning state by hand.
`apm clean --generations` only cleans the invoking user's package profile; no
supported command prunes system-package or sysroot generations. If those
profiles are the material consumer, preserve rollback capacity and expand or
reimage the host until a supported pruning command is available.

## Report an issue

Include the system version, active generation, exact command and exit status,
failed units, and relevant journal section. Redact registry credentials,
metadata payloads, host facts, and service secrets before sharing logs.
