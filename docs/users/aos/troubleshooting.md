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

## Metadata was accepted but activation did not complete

Check full evaluation:

```sh
systemctl status aos-eval.service
journalctl -b \
  -u aos-eval.service \
  -u aos-graph-compile.service \
  -u aos-activate.service
test -s /run/aos/manifest.json
cat /run/aos/activation.json
readlink /var/lib/profiles/system/current
```

The manifest is an intermediate result. A complete transaction must also
compile the package graph, fetch and render authenticated projections, resolve
credential references, materialize a numbered EROFS lower, switch `/etc`,
and publish a matching activation record. The journal's
`config-eval.class=...` tag distinguishes assertion, undefined-option,
conflict, provider, ABI, fetch, resource-limit, and convergence failures.

If the activation record is `degraded`, inspect its dropped packages and
failed units. Re-running the same transaction retries it; the graph compiler
does not treat degraded or stale evidence as complete. If no new current
pointer was committed, the previous configuration remains live.

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

- authenticated `host.nix` enables SSH directly or selects
  `aos.roles.server`/`aos.roles.edge`;
- the active configuration generation contains the expected
  `/etc/ssh/authorized_keys/USER`;
- the SSH port is open in `aos.firewall.allowedTCP`;
- the network interface name and address match the target;
- the hypervisor or cloud security policy also allows the port.

Cloud metadata public keys are available to evaluation as the typed
`host.facts.ssh_authorized_keys` input. They are not implicitly trusted as an
account policy: verify that a trusted module deliberately projected them to the
expected user's authorized-keys file. Presence in instance metadata alone is
not proof that login is configured.

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
`apm clean --generations --keep N` prunes the invoking user's package profile.
`apm clean --system --generations --keep N` prunes machine-wide package and
configuration generations, always preserving each current generation; follow
it with `apm gc` to reclaim unreachable store paths. There is no supported A/B
image-generation prune command, so preserve image rollback capacity and expand
or reimage the host if the image profile is the material consumer.

## Report an issue

Include the system version, active generation, exact command and exit status,
failed units, and relevant journal section. Redact registry credentials,
metadata payloads, host facts, and service secrets before sharing logs.
