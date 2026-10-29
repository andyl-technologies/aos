# Image build

## Definitions and evaluation

Container definitions are typed submodules of the same system evaluation that
produces bootable disk images. The OCI backend
(`pkgs/containers/_aos-oci-backend/module.nix`) declares
`aos.containers.{enable,default,systemPackageSlice,definitions}` and enables an
`aos` default definition. `modules/image/container.nix` builds every definition
and exports:

```text
systems.<variant>.build.containers.<name>
systems.<variant>.build.defaultContainer
containerImages.<name>          (alias of systems.server.build.containers)
```

A built container exposes the multi-platform `ociIndex`, per-platform layouts
and archives, evidence, `publicationInputs`, and its `checks`. The builder
consumes only an explicit userland projection of the system, so sharing the
evaluation does not retain the kernel, initrd, bootable toplevel, or disk
layout.

The definition schema (`container/schema.nix`) owns the name and platforms,
package roots, an ordered named layer plan, users, groups, directories, files,
executable facade links, the OCI entrypoint, command, environment, user,
working directory, stop signal, and annotations, package-management policy,
size budgets, and publication identity. There is no base-image option. Authored
files enter as Nix store content and are public image content; secrets have no
representation in the schema.

### The `aos` image

`aos-definition.nix` defines the image from three root groups:

| Layer | Roots |
|---|---|
| `runtime-core` | glibc, the GCC runtime libraries, and CA certificates |
| `system-userland` | Bash, coreutils, findutils, grep, gawk, fzf, and `aos.containers.systemPackageSlice`, minus the runtime core |
| `aos-cli` | `apm` and `aos-package-runtime`, minus the preceding roots |

`aos.containers.systemPackageSlice` is set by the system's package module
(`systems/_base-packages.nix`), and an assertion requires every selected package
to also be in `environment.systemPackages`, so the image cannot drift from the
system's package definitions. The `aos` and `apr` CLIs are separate packages;
users install them with APM inside the container. The image copies the
system's APM registry configuration from `/etc/apm/`, so it trusts the same
registries and channel as the system variant.

The runtime sets `AOS_RUNTIME=container`, runs as `0:0` in `/work`, and uses
`/usr/bin/aos-container-init` as its entrypoint with an empty default command.
The PATH puts the user's APM profile ahead of the baked facade so packages
installed later can add commands. Budgets cap the closure at 768 MiB and the
image at eight layers.

## Closure layers

A closure layer is defined by `roots` and `subtractRoots`:

```text
contents = closure(roots) - union(closure(subtractRoots))
```

`oci/closure-layer.nix` reads Nix's structured `exportReferencesGraph` output
(store path, NAR hash and size, references). The realized graph is
authoritative: derivation inputs can include build-only tools, and reference
scrubbing can remove declared dependencies. The builder sorts full store paths,
verifies every source exists, rejects collisions, and stages each as a relative
`nix/store/<basename>` entry. Store layers are additive and never need OCI
whiteouts. Every layer records an inventory binding store paths to the layer
that owns them, and layers in one image must be disjoint.

Layer reuse is explicit. The layer plan names cumulative cohorts, so changing
one package invalidates only the cohorts whose exact contents changed; there is
no automatic greedy packing, which would churn unrelated layer digests.

### Archive ABI

The archive policy is part of the layer ABI, `aos.container.layer/v2`, and lives
in one place, `archiveScript` in `oci/common.nix`. It requires AOS GNU tar 1.35
and AOS gzip 1.14 and fails if either version differs:

```sh
find root -mindepth 1 -printf '%P\0' | sort -z > members
tar -C root --null --verbatim-files-from --no-recursion --format=gnu \
  --mtime=@1 --clamp-mtime --owner=0 --group=0 --numeric-owner \
  --no-acls --no-selinux --no-xattrs --hard-dereference \
  -cf layer.tar --files-from="$PWD/members"
gzip -n -9 -c layer.tar > layer.tar.gz
```

- The member list is explicit and sorted; there is no implicit root member and
  no recursive traversal.
- `--hard-dereference` keeps host store optimization from leaking
  nondeterministic hard links into a layer.
- Devices, FIFOs, and sockets are rejected before archiving.
- `gzip -n` omits the file name and timestamp.

The uncompressed tar's SHA-256 is the DiffID; the compressed blob's SHA-256 is
the descriptor digest. The frozen fixture checked by `checks.container.phase0`
is:

```text
uncompressed sha256:6e30729d0413d5fb0dba4d0573093a4950e81cd45d7a9ebc2f62f09746b07ea5
gzip         sha256:1ec9791d8b0b3458830e5156881293d288941e793bb73790f85ad35f168a51d0
```

Changing any command, tool version, flag, fixture byte, or expected hash is a
layer ABI change. The ABI is root-owned; non-root ownership would need a new
ABI version.

## Facade and metadata layers

After the closure layers, the image adds two small layers:

- The facade layer (`container/facade-layer.nix`) scans each selected package's
  `bin` and then `sbin` directory in package order, keeps the first executable
  for each name, records every shadowed collision, and emits `/usr/bin`
  symlinks into `/nix/store`. Collisions must be listed in
  `allowedFacadeCollisions`.
- The root metadata layer (`oci/metadata-layer.nix`) provides the scratch
  filesystem: directories, minimal account files, CA trust aliases, OS release
  identity, profile and shell files, APM and Nix state directories, the
  embedded closure registration stream, and the init program. Metadata is
  typed directories, text files, and symlinks; there is no arbitrary
  source-tree import. Runtime-owned files such as hostname, hosts, and the
  resolver configuration are omitted.

The image assembler (`oci/image-layout.nix`) writes canonical compact config and
manifest JSON, records ordered DiffIDs, copies every blob into
`blobs/sha256/<digest>`, and emits `index.json` and `oci-layout`. Outputs are
self-contained regular files. `oci/multi-platform-index.nix` combines
independently built platform manifests into one index without repacking layers,
recording the exact AOS target system in an annotation. Docker archives are a
deterministic adapter over the same blobs.

## Runtime initialization

The entrypoint is a Bash script generated by `container/init-script.nix`. It
uses a daemonless, single-user local Nix store (`NIX_REMOTE=local`); no Nix
daemon is present or contacted. Holding
`/nix/var/nix/.aos-container-init.lock` exclusively, it:

1. validates the baked root list against the embedded closure;
2. removes readiness state from an earlier PID-1 lifetime;
3. publishes a fresh GC-root directory with one symlink per baked root and
   replaces `/nix/var/nix/gcroots/aos-container-baked`;
4. creates the local Nix database if absent and loads the embedded registration
   stream;
5. checks every baked root's validity;
6. creates the APM, XDG, and profile directories;
7. records a persistent read-only marker when probes show the store cannot be
   mutated;
8. resumes the native container deployment (`aos-package-runtime
   container-startup`), which may select an installed init program;
9. publishes a readiness marker bound to the current PID-1 start time;
10. releases the lock and executes the requested argv, the selected init, or
    the default shell, without reparsing it through a shell.

When the Nix state directory itself is read-only, no transaction is possible:
init runs the requested command directly from the embedded store, and clients
classify the container as read-only without waiting.

Roots are published before the database can report any baked path as valid, so
a concurrent `exec nix-store --gc` cannot collect a freshly registered closure.
Reconciliation runs on every start, which also repairs an operator-mounted
empty Nix state directory. Read-only checks probe real mutations rather than
mode bits, because root passes `test -w` on a read-only mount.

The marker files are versioned contracts:

```text
/nix/var/nix/.aos-container-ready
schema=aos.container.ready/v1
pid1_start_time=<field 22 of /proc/1/stat>

/nix/var/nix/.aos-container-read-only
schema=aos.container.read-only/v1
```

A runtime can start a second process while the entrypoint is still
initializing, and that process does not inherit PID 1's environment. Every
APM process with `AOS_RUNTIME=container` therefore consults the filesystem
(`aos-package-manager/src/container_admission.rs`): it waits for a readiness
marker that matches the current PID 1, takes the init lock in shared mode, and
derives read-only admission from write probes and the persistent marker.
Malformed markers fail closed. Host-only package operations are rejected before
the wait.

The entrypoint is exec-only, not a supervisor: the requested program becomes
PID 1 and handles its own signals and child reaping. Workloads that need
generic reaping use the runtime's init option (such as Docker `--init`) or an
init package installed through APM.

Images never contain registry credentials, signing keys, private trust anchors,
or agent sockets. Producer credentials enter a container only through runtime
mounts and environment chosen by the operator.
