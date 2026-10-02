# Configure an AOS host

AOS takes machine-specific policy from `host.nix` without requiring each user
to build a private system image. The public image remains an early preview, but
the runtime configuration-generation path is active.

| Configuration path | Use it for | Current behavior |
| --- | --- | --- |
| Metadata `host.nix` under `aos.provisioning.storage` | First-boot partition, array, and volume layout | Applied once, then checked for drift |
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

Partitions on two disks can form an MD mirror, and a mirror can carry `/var`
itself. The array is created in the same first-boot transaction and assembled
by the initrd on every later boot:

```nix
{
  aos.provisioning.storage = {
    partitions = {
      var = {
        sizeMin = "32G";
        sizeMax = "32G";
        grow = false;
      };
      var-mirror = {
        device = "/dev/disk/by-id/virtio-aos-mirror";
        sizeMin = "32G";
        sizeMax = "32G";
      };
    };
    arrays.var = {
      level = "raid1";
      members = [ "var" "var-mirror" ];
    };
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
user and system scopes, upgrades, and rollback, and [Configure package
registries](registries.md) for origin and trust policy.

## Discover package configuration

Package option and service reference is generated from the exact signed Nix
interface selected by a registry release. It is not maintained in a parallel
Markdown page. Browse a remote registry before installation:

```sh
apm docs search proxy --hub https://hub.example \
  --registry acme/production
apm options search virtualHost --hub https://hub.example \
  --registry acme/production
apm schema nginx --hub https://hub.example \
  --registry acme/production
```

After installation, the same commands default to the documentation Nix object
retained by the active package profile. They continue to work without a
registry, cache, or network connection:

```sh
apm docs show nginx
apm options show aos.services.nginx.enable --package nginx
apm docs man nginx --install
apm docs serve
```

Editors can use that same closed schema and exact package identity through the
standard-LSP server:

```sh
aos language-server
```

Configure an editor to start that command over stdio. Completion, hover,
definition, links, symbols, diagnostics, and quick fixes are advisory because
the language server never evaluates an editor buffer. Review the authoritative
result with `apm config diff` before applying it. `apm options complete` exposes
the same bounded option-path completion to shells and other editor clients.
The read-only `aos/packageDocumentation/abilityGraph` extension accepts one
exact loaded package/version plus the canonical shared graph query object. Its
public-only slice uses the same node identities, relationship meanings, query
bounds, and limitation diagnostics as `aos ability inspect` and the Hub. It
does not report deployment authorization or live provider availability.

## Understand runtime `host.nix`

Runtime activation follows one transaction:

```text
accepted host.nix + facts + retained native module sources
  -> typed desired-package selection
  -> signed registry acquisition of missing packages and native companions
  -> complete native graph evaluation
  -> journaled effects, including configuration lower and services
  -> one committed system-profile generation
```

Selection reads explicit package requirements before package-owned options are
checked. It does not infer providers from undefined-option errors. Full native
evaluation checks authenticated modules, release requirements, handlers, and
effect dependencies before execution.

Built-in server and edge roles contribute conditional package requirements.
Enabling a role can acquire its SSH and time-synchronization packages through
configured registries without rebuilding the image. Their configuration and
package selection commit together.

The configuration-lower effect retains and mounts an EROFS `/etc` lower before
its dependent consumers. Other declared dependencies order state preparation
and service realization. The native journals record completed effects and
pending recovery; a failed activation does not publish a new `current` pointer.
Recovery completes before another change is accepted.

Image generations own the kernel, initrd, and A/B slot. Native system-profile
generations retain selected packages, module sources, operator input, and
evaluated deployment state. Subsequent boots recover and reconcile the latest
committed profile rather than replacing it with the image's initial selection.

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
  aos.services.nginx = {
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
inspection. Subsequent boot reconciliation uses the generation-pinned snapshot;
edited worktree files are admitted by an explicit `apm config apply` or
`apm switch` transaction.

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

APM evaluates the complete operator worktree with the retained host input and
running image's native module library, then compares it with the committed
generation. Use `apm config add` or `apm config replace` to stage edited input.

When selected packages are already installed, native preview reports added,
changed, and removed effects. If packages must be acquired first, it reports
those names and stops before full graph evaluation. Preview neither downloads
those missing packages nor activates effects or publishes a generation. Put
the global `--json` option before the subcommand for machine-readable output:

```sh
apm --json switch --dry-run
```

Apply a reviewed configuration with the same evaluator and checked activation:

```sh
apm switch
```

The switch also reconciles `aos.apm.desiredPackages`. Typed selection runs before
authenticated package acquisition and complete native evaluation, so a module
can name a new package and set its package-owned options together. Package
selection and enabled effects commit in the same generation. Dependency modules
and available sibling outputs do not install unused payloads.

Already installed packages are retained through their committed native
sources and authenticated envelopes. Missing roots use normal configured
registry resolution, download verification, and native companion admission.
The host input authorizes its configuration bytes; each acquired package
still needs its own registry release proof.

Runtime operator modules are retained with the committed generation; editing
the worktree alone does not change active or rebooted state. These commands do
not rewrite the metadata-delivered source. Inspect the command error and native
controller journal when acquisition, evaluation, admission, or an effect fails.

## Inspect configuration state

```sh
apm config status
systemctl status aos-ability-host-controller.service
journalctl -b -u aos-ability-host-controller.service
readlink /var/lib/profiles/system/current
cat /var/lib/profiles/system/current/evaluation.json
cat /var/lib/profiles/system/current/native-deployment.json
```

Evaluation alone does not prove activation. The native generation and effect
journals under `/var/lib/profiles/system/deployment` record committed state and
recovery. Check the controller result, failed units, and application health as
well as the current pointer and its retained publication marker.

Release maintainers who need to change the golden image should use
[Build and customize release images](../../maintainers/system-images.md).
