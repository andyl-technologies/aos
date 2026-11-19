# Host configuration

An AOS host is configured from `host.nix`, a literal Nix module delivered by the
platform at boot, together with operator modules added at run time. The host
evaluates that configuration against downloaded, authenticated package modules
and pre-built binary closures. It never builds: evaluation produces data, and
activation executes checked effects over store paths acquired from signed
registries. The result is a journaled system-profile generation that can be
committed or rolled back as a unit.

The operator-facing behavior (delivery channels, trust modes, the storage
schema, diagnostics, and runtime changes) is documented in
[Understand and operate `host.nix`](../users/aos/host-nix.md). Secrets are in
[Manage secrets on AOS](../users/aos/secrets.md), and image upgrades and
rollback in [Upgrade and roll back a host](../users/aos/upgrades.md).

## Image and host boundary

The golden image supplies capabilities and trust roots: the kernel, initrd, the
immutable EROFS root, the package-module library, the selected provider
packages, registry configuration, and any baked configuration-signing keys.
`host.nix` supplies host policy: storage, networking, desired packages, and
service configuration. Image modules are evaluated at build time; host policy
is evaluated on the host, so changing it never requires a new image.

The host therefore has two independent generation axes:

- the image slot, A or B, staged and selected by `aos-boot-runtime` and changed
  only by image upgrades; and
- the configuration generation under `/var/lib/profiles/system`, changed by
  host configuration and package changes.

## Boot pipeline

```text
initrd: aos-ability-initrd-controller
  detect platform           aos-platform-metadata::detect
  acquire metadata          aos-platform-metadata fetchers
  authorize host.nix        aos-platform-metadata::{policy, trust}
  plan and commit storage   aos-storage-layout, storage provider packages
  switch root
stage 2: aos-ability-host-receiver
  verify the initrd handoff
stage 2: aos-ability-host-controller
  adopt authorized sources (first activation; aos-cli boot_configuration)
  select and acquire desired packages from signed registries
  evaluate the complete native graph           aos-deployment::evaluation
  execute effects, mount the /etc lower        aos-deployment, aos-configuration-image
  commit the system-profile generation         aos-deployment::transaction
```

Each controller step is a typed provider operation selected from the image's
resolved ability stage, not a separately managed systemd unit. The ability and
effect engine itself is part of the runtime ability infrastructure.

### Metadata acquisition and authorization

`aos-platform-metadata` detects the platform from DMI data and a config-drive
probe, then fetches user data and facts through a `PlatformFetcher`: the AOS
metadata ISO, NoCloud, config drive, a QEMU `fw_cfg` blob, AWS IMDSv2, or other
cloud metadata services. Untrusted bytes stay in private transaction scratch.
The policy step authorizes the whole input and publishes only typed results;
exact `host.nix` bytes and early-network facts cross operations through
protected typed outputs. Facts are rendered to a separate `host-facts.nix`
input; they are data, so a fact such as a provider SSH key grants nothing until
`host.nix` or an image module uses it.

In signed trust mode, `aos-platform-metadata::trust` verifies a detached SSHSIG
over the exact `host.nix` bytes in the `aos-config` namespace against the
image's `trusted-config-keys.d/<operator>.pub` keys, before any evaluation in
the initrd or stage 2. The namespace is distinct from Git signing, preventing
cross-protocol replay. Platform trust mode treats the selected metadata channel
as the authority.

### Storage commit

The initrd evaluates only the closed `aos.provisioning.storage` projection of
`host.nix` against image-frozen module sources; unknown fields fail before any
disk is touched. `aos-storage-layout` validates and canonicalizes the plan.
The storage provider commits it once and writes a provenance marker; later
boots dry-run the committed plan and report it as coherent, divergent, or
unavailable rather than repartitioning.

## Evaluation

`aos-deployment::evaluation` evaluates the generic module library, the
authenticated package modules of the resolved dependency closure, and the
operator inputs. Package modules are fixed NAR inputs exported from the
selected store, and `aos-deployment::nix` runs the AOS-built `nix-instantiate`
in a cleared environment with:

```text
--eval --strict --json --pure-eval
--option restrict-eval true
--option substituters ""
--option allow-import-from-derivation false
--option allowed-uris "path:/nix/store/ ..."
```

so evaluation can read only the exported inputs and cannot build, substitute,
or fetch. Package selection is typed (`aos.apm.desiredPackages`): the
controller acquires the selected packages and their native companions first,
then evaluates the complete graph, so package-specific options are checked only
after the owning module is admitted. Each package declares its compatible host
release, and evaluation checks those requirements against the fixed host
release.

Secrets never enter the evaluated value graph. `host.nix` holds only opaque
`secretRef` handles, which activation resolves when it places credential
material.

## Activation and generations

`aos-deployment::transaction` coordinates durable generations with the effect
journal:

```text
prepared { sequence, document, packages }
committed { sequence, outputs }
reconciliation-prepared { sequence, attempt, content }
reconciled { sequence, attempt, outputs }
```

A prepared generation retains its exact module transaction before dispatch.
The activation journal records the transaction identity, so a restart between
effect completion and commit does not repeat one-shot operations. The
committed journal record is the authoritative generation pointer; the profile's
`current` link is published from it after effects commit. A failed activation
publishes no new generation, and pending work is recovered before another
change. Generation and effect journals live under
`/var/lib/profiles/system/deployment`.

`/etc` is an effect like any other. `aos-configuration-image` renders the
generation's typed configuration files without following destination symlinks,
publishes a deterministic EROFS lower image with a durable receipt under
`/var/lib/aos/configuration-lowers`, rechecks it on reuse, and at boot mounts
the verified image of the explicitly bound, committed generation.

Runtime operator modules (`apm config add`, `apply`, `replace`, and
`apm switch`) feed the same evaluation and transaction path as the boot-time
`host.nix`, and are retained as immutable inputs of the generation that
uses them.
