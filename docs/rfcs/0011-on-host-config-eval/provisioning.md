# Provisioning from `host.nix`

`host.nix` is the sole operator-authored configuration language for AOS. Cloud
user-data is a transport for that file, not a second provisioning format.
Storage, packages, services, users, networking, and runtime policy are all
declared in the same module and resolved by the same AOS module system.

This document specifies the part of `host.nix` that must be evaluated before
switch-root, the one-time storage commit protocol, metadata acquisition and
authentication, and the boundary between the golden image and host policy.

## Invariants

1. **One configuration source.** The metadata agent accepts literal `host.nix`
   bytes. It never accepts a JSON storage plan, Ignition document, Butane
   document, cloud-init configuration, or raw `repart.d`.
2. **Transport is not configuration.** A provider-size escape hatch may carry
   only `{ url, sha256, signature_url }`. It locates and authenticates the
   exact `host.nix` bytes; it cannot express host state.
3. **Authenticate before interpretation.** The selected `platform` or `signed`
   policy authorizes the exact `host.nix` bytes before the initrd evaluates
   `aos.provisioning` or mutates a disk.
4. **Closed early projection.** The initrd evaluates only the declared
   `aos.provisioning` subtree. Undeclared stage-2 configuration is neither
   merged into the result nor forced.
5. **Validate twice.** Nix option types validate the operator-facing language.
   A versioned Rust data contract independently validates the evaluated plan
   before rendering `repart.d`.
6. **Provision once.** Automatic storage mutation ends when a committed GPT
   provenance marker exists. Later configuration changes are advisory and
   require factory reset or reinstall to apply.
7. **The fallback uses the same schema.** With no `host.nix`, AOS evaluates the
   image's default `aos.provisioning.storage` module and feeds the result
   through the same Rust validator and renderer. There is no separately
   maintained baked `repart.d` policy.
8. **No build on the host.** Early and full evaluation are pure value
   computation over the in-image base library and authenticated source. They
   cannot instantiate or realize derivations.

## Why a restricted initrd evaluation exists

`/var` must exist before switch-root, but the full configuration evaluator runs
after switch-root because package configuration modules may need registry
resolution and networking. Deferring all of `host.nix` therefore makes
first-boot storage configuration impossible.

The storage projection is closed: it uses only the base module library,
`host.nix`, and image-provided provisioning defaults. It has no package roots,
registry fixpoint, network access, or `system.build` output. Stock Nix runs in
the measured initrd with:

```text
nix eval --json
  --option restrict-eval true
  --option allow-import-from-derivation false
  -I <eval-root>
  -I <base-lib>
  -I <authenticated-host.nix>
  -f <eval-root>/entry.nix
```

The AOS module engine is intentionally non-strict for this projection:

- no evaluation-global `_module.strict = true`;
- no evaluation-global `_module.freeformType`;
- no read of `config.system.build.*`;
- only `config.aos.provisioning` is forced.

These are compatibility invariants, not incidental implementation details.
A regression check evaluates a `host.nix` containing an undeclared,
`throw`-valued stage-2 option and proves that reading the provisioning subtree
does not force it.

## Operator schema

The first public provisioning domain is storage:

```nix
{
  aos.provisioning.storage.partitions = {
    swap = {
      type = "swap";
      sizeMin = "2G";
      sizeMax = "2G";
    };

    var = {
      type = "var";
      label = "var";
      sizeMin = "4G";
      grow = true;
      format = "ext4";
    };
  };
}
```

`aos.provisioning` is a lifecycle namespace, not an initrd namespace. Future
children are admitted only for genuinely one-time host enrollment. Normal
filesystems, networking, users, services, and packages stay in their domain
namespaces and are reconciled by full stage-2 evaluation.

The v1 partition contract contains:

```text
device     null or a stable absolute /dev/disk/by-id path
label      validated GPT label, defaulting to the logical attribute name
type       linux-generic, var, swap, or a non-protected canonical raw GPT GUID
sizeMin    systemd size string
sizeMax    optional systemd size string
weight     positive integer
format     null, ext4, vfat, or swap
uuid       optional operator-declared partition UUID
grow       whether this partition consumes remaining free space
growFs     whether repart may grow an existing filesystem
priority   deterministic placement priority
```

The root-disk default (`device = null`) is resolved from the parent of the
booted `root-a` partition. Explicit devices must be stable paths. The renderer
groups partitions by resolved device and invokes `systemd-repart` once per
device.

The validator rejects:

- the reserved provenance type and labels;
- frozen ESP, root, or verity labels/types;
- invalid or globally duplicate labels;
- invalid size syntax;
- more than one unbounded grow partition per device;
- incompatible type/format pairs;
- non-stable or relative device paths;
- formats whose tools are absent from the initrd;
- raw INI, arbitrary commands, and caller-chosen output paths.

`/var` remains fixed substrate in v1. Measured images leave it raw so
`aos-var-crypt` can create LUKS2 and enroll the TPM token. Unmeasured images
format it as ext4. General filesystem mounts remain stage-2 configuration.

## Metadata and trust

The native metadata agent performs:

```text
aos metadata detect     # platform/config-drive discovery
aos metadata fetch      # exact user-data + detached signature + facts
aos metadata authorize  # platform/signed policy -> accepted host.nix
aos metadata eval-provisioning
                        # restricted eval -> typed plan JSON
```

The stash under `/run/aos-metadata` contains:

```text
platform.env
user-data
user-data.sig                 # optional detached SSHSIG
host.nix                      # policy-accepted exact bytes
facts.json
.metadata-result.json
.provisioning-result.json     # trust evidence and host.nix hash
provisioning-plan.json        # evaluated, normalized data
repart.d/                     # generated per-device definitions
```

`/run` is moved across switch-root. Stage 2 verifies the recorded hash before
evaluating the same `host.nix`; it never refetches mutable metadata.

### Platform policy

`platform` trusts successful delivery through the detected cloud metadata
service or deployment-owned config drive. This is the default for an
unmodified golden image because the control plane already controls instance
creation, attached disks, and user-data.

### Signed policy

`signed` requires a detached SSHSIG over the exact `host.nix` bytes. The
verification root is measured image state and cannot be supplied by the file
it authenticates. A generic golden image therefore carries a vendor or fleet
provisioning root; customer/operator keys are admitted through a signed
delegation chain. The delegation is authentication material, not host
configuration.

Neither policy may be selected or downgraded by `host.nix`.

## Boot and commit protocol

```text
INITRD
  detect -> network if required -> fetch -> authorize exact host.nix
    |
    +-- committed provenance marker present?
    |     yes: skip metadata and provisioning; do not mutate
    |
    +-- pending provenance marker present?
    |     yes: fail closed for explicit recovery
    |
    `-- no:
          host.nix present -> restricted aos.provisioning eval
          host.nix absent  -> restricted default provisioning eval
                    |
                    v
              Rust validation
                    |
                    v
         render per-device repart definitions
                    |
                    v
         dry-run every target before any mutation
                    |
                    v
         create/reserve pending provenance marker
                    |
                    v
         apply every device; verify resulting topology
                    |
                    v
         relabel pending marker as operator-v1 or fallback-v1
                    |
                    v
         /var encryption/format -> mount -> switch-root

STAGE 2
  verify host.nix byte binding
  full resolve/eval -> packages, /etc, units, networking, users
```

The reserved GPT marker is whole-machine state on the root disk. Its labels are:

```text
aos-provisioning-pending-v1
aos-provenance-operator-v1
aos-provenance-fallback-v1
```

Only a committed provenance label means provisioning completed. Creating the
partition as `pending` before the mutating passes reserves space ahead of a
grow-to-fill partition without falsely recording success. A crash or device
failure leaves `pending`; the next boot refuses an automatic replay so recovery
can inspect which devices committed before choosing resume or factory reset.

On the provisioning boot, authorization, evaluation, validation, preflight, or
mutation failure blocks switch-root and emits a console diagnostic. The
mutating `systemd-repart` exit status is always propagated.

On later boots the committed GPT marker is sufficient: missing metadata cannot
make a working host unavailable, and no automatic evaluation, dry-run, or
mutating pass runs. A stage-2 administrative command may compare a newly
supplied plan and report that factory reset is required, but it has no path
back into initrd disk mutation.

## Golden-image boundary

The golden image supplies mechanisms and roots of trust, not workload or host
policy. The detailed contract is in
[`image-host-boundary.md`](image-host-boundary.md).

Image-owned inputs include the kernel, initrd, boot chain, root image, verity,
the evaluator/base module ABI, bootstrap networking and storage tools, and
initial authentication roots. `host.nix` owns storage intent, roles, desired
packages, identity, users, networking, services, runtime security, observability,
and other reconciled policy.
