# Configure an AOS host

AOS takes machine-specific policy from `host.nix` without requiring each user
to build a private system image. The public image remains an early preview, but
the runtime configuration-generation path is active.

| Configuration path | Use it for | Current behavior |
| --- | --- | --- |
| Metadata `host.nix` under `aos.provisioning.storage` | First-boot partition layout | Applied once, then checked for drift |
| Other metadata `host.nix` settings | Hostname, networking, users, access, services, and desired packages | Purely evaluated, materialized, and atomically activated as a configuration generation |
| `apm` | User packages and implemented machine-wide package reconciliation | Active at runtime |
| System modules in the source tree | Golden-image and release policy | Maintainer workflow, evaluated when the image is built |

Keep a tested console or image-baked break-glass path while changing network or
access policy. A failed stage-2 transaction retains the previous generation,
but a valid configuration can still make a host unreachable.

## Configure first-boot storage

Deliver `host.nix` through a supported metadata transport. This example keeps
swap at 1 GiB, requires at least 8 GiB for `/var`, and creates a fixed data
partition on the boot disk:

```nix
{
  aos.provisioning.storage.partitions = {
    swap = {
      sizeMin = "1G";
      sizeMax = "1G";
    };

    var.sizeMin = "8G";

    data = {
      label = "data";
      type = "linux-generic";
      sizeMin = "20G";
      sizeMax = "20G";
      format = "ext4";
      priority = 1000;
    };
  };
}
```

For an additional disk, identify the target by a stable `/dev/disk/by-id/...`
path:

```nix
{
  aos.provisioning.storage.partitions.data = {
    device = "/dev/disk/by-id/virtio-aos-data";
    label = "data";
    sizeMin = "20G";
    sizeMax = "20G";
    format = "ext4";
  };
}
```

AOS preflights every target before changing any disk. The accepted plan is
committed on the first successful provisioning boot. Later changes are
reported as drift rather than applied automatically.

The [`host.nix` guide](host-nix.md) documents every storage field, metadata
delivery, signatures, multi-disk layouts, first-boot state, drift, and
recovery. Read it before deploying a storage policy.

## Install packages at runtime

Use `apm` instead of baking ordinary tools into a private image:

```sh
apm search curl
apm install curl jq
apm list --installed
```

Machine-wide package sets can be reconciled from a reviewed desired-state
file with `apm install --system --from`. See [Manage packages](packages.md) for
registry trust, user and system scopes, upgrades, and rollback.

## Understand runtime `host.nix`

Runtime activation follows one transaction:

```text
host.nix + facts + ABI-pinned base library
  -> pure resolve/evaluate fixpoint
  -> authenticated package fetch and signed config render
  -> secretRef resolution
  -> EROFS /etc lower in gen-N
  -> atomic pointer and /etc switch
  -> unit reconciliation and activation record
```

The resolver imports only authenticated package `config` outputs compatible
with the running image ABI. Package render failures use the documented soft
degradation path and are recorded in the projection; evaluation, credential,
or pre-swap failures leave the active generation unchanged.

The server and edge images retain the package closures needed by their
built-in runtime roles. Enabling `aos.roles.server` or `aos.roles.edge` in an
authenticated `host.nix` can therefore start SSH and time synchronization
without rebuilding or downloading a different image. Retained role packages
remain absent from the generation-zero manifest and interactive command path
until host policy selects their services.

After the atomic `/etc` switch, activation applies the new `tmpfiles.d` rules
before reconciling services. Runtime roles may therefore introduce required
state directories in the same transaction that starts their daemons.
Changes to generated service scripts replace the corresponding image unit as
one activation artifact. Settings that disable an image-baked file or service
create a generation-local overlay deletion, so the immutable lower copy does
not remain active merely because it exists in the image.

Image and configuration generations are independent. An image generation owns
the kernel, initrd, base module library, evaluator, and A/B slot. A
configuration generation owns the evaluated manifest and EROFS `/etc`
lower and records the image generation and module ABI it was built against.
Same-ABI rollback can reactivate retained configuration directly. Cross-ABI
rollback re-evaluates retained `host.nix`, facts, and authenticated package
modules against the running image instead of replaying an incompatible `/etc`.

## Supplement `host.nix` at runtime

Runtime modules layer local operator intent over the authenticated platform
`host.nix`; they never overwrite or copy it. AOS discovers safe `.nix` files
recursively beneath `/var/lib/aos/config/modules.d`, snapshots the complete
tree into the Nix store, and passes every public entrypoint directly to the
same module evaluator. Names beginning with `_` are private helper files and
directories: public modules may import them, but AOS does not evaluate them as
entrypoints.

For a package installed through `apm`, put only its configuration in a module:

```nix
{
  nginx = {
    enable = true;
    virtualHosts.health = {
      listen = [8080];
      locations."/"."return" = {
        code = 200;
        body = "healthy\n";
      };
    };
  };
}
```

Then stage, review, and activate the complete set:

```sh
apm config add ./nginx.nix
apm config diff
apm config apply
apm config status
```

Alternatively, add `aos.apm.desiredPackages = ["nginx"];` to the module so
package selection and configuration occur in the same transaction. Use
`replace` and `remove` to edit desired state, and `discard` to restore the
worktree from the active immutable snapshot. A failed evaluation or activation
leaves the current generation live; the edited worktree remains dirty for
inspection. Reboot, rollback, ordinary `apm switch`, and cross-ABI
re-evaluation use the generation-pinned snapshot, never unsaved worktree bytes.

Runtime modules have full stage-2 local-root operator authority but cannot
change `aos.provisioning.*`: storage provisioning remains exclusively sourced
from authenticated boot-time `host.nix`. The initial runtime-set trust mode is
`local-root`; signed-set ingestion is rejected until AOS can retain and verify
a signature receipt over the complete set descriptor.

Preview a candidate without fetching its runtime closure or touching the live
generation:

```sh
apm switch --dry-run
```

By default, APM evaluates the staged runtime `host.nix` with the running
image's base library and module ABI, and compares it with `current`. Use
`--from ./host.nix` to preview edited input. `--diff-against` accepts
`current`, `gen-N`, or an explicit manifest path.

The human report includes `/etc` additions, changes, and removals; unit
start/restart/stop actions; store paths to fetch; and the provider-resolution
trace. Put the global `--json` option before the subcommand for
machine-readable fields:

```sh
apm --json switch --dry-run
```

Apply a reviewed configuration with the same evaluator and graph compiler:

```sh
apm switch --from ./host.nix
```

The switch also reconciles `aos.apm.desiredPackages`: authenticated rendered
unit artifacts are attached to the candidate generation, selected package
targets are enabled and started after the `/etc` swap, and targets removed from
the desired set are stopped. Packages bundled in the image remain inert unless
the active host configuration selects them.

Selection prefers an authenticated configured registry. If no registry
publishes a selected name, AOS may use the exact package and config companion
from the active image-seeded package profile. This is the supported
bootstrap/recovery and deliberate-offline path: every local NAR is verified
against the immutable package seed reached through the booted image's lower
store. Writable profile metadata must exactly match that seed, so changing a
profile record cannot authorize a different module. Missing or mismatched
image-local content fails closed instead of being fetched from an unrelated
registry.

`--from` selects the input for this transaction; it does not replace the
metadata-delivered policy or its last-known-good cache. Update and, in signed
mode, sign the authoritative metadata input before relying on the change after
a reboot. For a standalone file in signed mode, also use
`--require-signed-host-nix` and point `--trusted-config-keys-dir` at the
applicable trust-anchor directory.

Terminal evaluation failures retain a stable `config-eval.class` journal tag
and distinct exit code:

| Exit | Class |
| --- | --- |
| `10`-`12` | Assertion, undefined option, or conflicting definitions |
| `13`-`14` | Missing provider or module ABI mismatch |
| `15`-`17` | Resource kill, non-convergence, or unsatisfiable provider cycle |
| `18` | Ambiguous provider |
| `19`-`20` | Fetch failure or unclassified evaluation error |
| `21`-`22` | Shadowed root or invalid contribution grant |

The default journal message is a one-line operator summary. Repeat the command
in verbose mode when the complete Nix trace is required.

## Inspect configuration state

```sh
systemctl status aos-eval.service
journalctl -b \
  -u aos-eval.service \
  -u aos-graph-compile.service \
  -u aos-activate.service
test -s /run/aos/manifest.json && echo "host input evaluated"
cat /run/aos/activation.json
readlink /var/lib/profiles/system/current
cat /var/lib/profiles/system/state.json

cat /var/lib/aos-provisioning/audit.json
if test -r /run/aos-metadata/storage-coherence; then
  cat /run/aos-metadata/storage-coherence
fi
```

An evaluated manifest proves only that module evaluation converged. The current
pointer and matching activation record prove that the generation was committed.
The record's `status` distinguishes `complete` from `degraded`; also inspect
the command result, failed units, and application health.

Release maintainers who need to change the golden image should use
[Build and customize release images](../../maintainers/system-images.md).
