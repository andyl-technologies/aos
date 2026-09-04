# Understand the package sandbox

AOS applies runtime confinement to systemd services published through a
package's `expose` contract. The contract contains the units, privilege
manifest, configuration interface, and supporting artifacts that APM verifies
and activates as one package target.

The sandbox limits what an authorized package can do after activation. It does
not establish where the package came from or whether its publisher is trusted;
configure that boundary through [package registries](registries.md).

## Know when the sandbox applies

The package sandbox applies only to workload services activated from verified
`expose` metadata. A package without `expose` has no APM-managed service, and
running an executable directly from a user or system profile does not put that
process inside the service sandbox.

Each exposed package has one lifecycle target:

```text
aos-pkg-<package-name>.target
```

The target owns the package's workload units and generated host-side helpers.
APM activates and removes the target as part of the machine-wide package
generation transaction. A unit explicitly marked for manual start is installed
but is not pulled into the target automatically.

## Start from default denial

An empty or omitted permission manifest selects the least-privilege defaults.
A confined service receives:

- its own package-backed root and private temporary directories;
- a private dynamic identity and user namespace where compatible;
- a private network namespace;
- an empty capability bounding set;
- closed device access except for explicitly generated necessities;
- a restricted named syscall profile;
- systemd filesystem, kernel, home, and privilege hardening;
- Landlock filesystem restrictions inherited across service execution; and
- generated TCP policy where ports are declared.

The package payload is the immutable lower layer of a per-service volatile
overlay. Writable state belongs in generated service directories or paths
explicitly granted by policy, not in the payload.

The actual generated unit is authoritative. The manifest, rendered unit, and
host policy are cross-checked during activation so a package cannot advertise a
narrow permission list while installing broader service directives.

## Read the privilege gradient

Permissions widen the default boundary. APM computes the result rather than
letting the package choose its own label:

| Label | Meaning |
| --- | --- |
| `sandboxed` | The exposed workload retains the default boundary with no declared holes |
| `sandboxed-with-holes (...)` | The listed grants weaken the default, but a meaningful boundary remains |
| `unconfined` | Root-equivalent grants make the package target a lifecycle wrapper rather than a security boundary |

`CAP_SYS_ADMIN`, privileged users, and writable system locations are
root-equivalent and force `unconfined`. Software such as k3s may legitimately
need that authority, but its workload isolation then comes from its own pod or
container model rather than the APM package sandbox.

Inspect both the signed request and the local policy decision before adding a
package to the desired machine-wide set:

```sh
apm info PACKAGE --system --permissions
apm policy PACKAGE --system
```

Do not infer confinement from a package description or service name.

## Review each permission

The effective privilege is the package request intersected with host policy.
The main permissions are:

| Permission | Effect |
| --- | --- |
| `network` | Selects a private, private-outbound, or host network model |
| `tcp-bind` and `tcp-connect` | Grants exact TCP ports to generated Landlock and eBPF policy |
| `capabilities` | Adds named Linux capabilities to the service boundary |
| `devices` | Opens exact device nodes through the generated device policy |
| `host-paths` | Bind-mounts named host paths read-only or read-write and extends filesystem policy |
| `cgroup-delegate` | Allows the service to manage descendant cgroups |
| `privileged-users` | Disables the private user-identity model |
| `static-users` | Uses authenticated named non-root service accounts instead of only dynamic identities |
| `kernel-modules` | Requests a host helper to load an allowlisted signed module |
| `syscalls` | Selects a named restricted, system-service, or privileged syscall profile |
| `security-label` | Selects the package's generated MAC label, subject to host policy |

Host networking is a significant downgrade. The process shares the host
network namespace, so per-package network identity cannot provide the same
separation. Filesystem, capability, syscall, credential, and other hardening
may still remain.

A read-write host path can be equivalent to full host authority when it covers
system configuration, service control, credentials, devices, or another
security-sensitive location. APM labels writable system locations
`unconfined`; operators should apply the same reasoning to application paths
that carry powerful control data.

## Understand host-fulfilled permissions

Some effects cannot be performed safely by the confined workload. AOS renders
narrow host-side services under the package target for approved kernel modules,
sysctls, firewall entries, network setup, MAC policy, and eBPF policy.

These helpers do not give the workload their own privileges. For example, a
package requesting `kernel-modules` does not receive `CAP_SYS_MODULE`; an
allowlisted host helper loads the named module. Enabling the package target
activates the helper, and disabling it removes reversible effects through the
same lifecycle boundary.

Review host-side permissions especially carefully. Kernel modules execute in
the kernel, global sysctls affect other services, and firewall changes alter
host exposure beyond the workload namespace.

## Distinguish store-backed and verity-backed roots

Normal confined services use a volatile `RootDirectory=` overlay backed by the
authenticated Nix store payload. Registry verification establishes the payload
identity when APM imports the closure, and the store is exposed read-only to the
workload.

An exposed package can instead publish a signed dm-verity root image. The
service uses `RootImage=` with the authenticated root hash and signature. This
adds block-by-block integrity checking while the service runs and is not
available for a package whose permissions require `unconfined` rendering.

A non-verity workload has authenticated admission and a read-only package root,
but not dm-verity verification of every block read at runtime. The read-only
view constrains the workload; it does not defend against an attacker who
already controls the host or its writable Nix-store backing. Choose a signed
package root image when that stronger property is required.

## Understand package measurement

On measured-boot systems, activation extends PCR 15 for every explicitly
installed machine-wide package with `expose` metadata. The event binds:

```text
H(package name || version || root digest || permission-manifest digest)
```

The event log is written to `/run/log/aos-packages.cel`. A verifier replays it,
checks the quote, and compares each tuple with the signed registry catalog. This
connects the active exposed-package set and its privilege declarations to the
boot measurements in PCRs 7, 11, and 12.

PCR 15 does not produce an individual package event for:

- user-profile packages;
- downloaded but inactive packages;
- implicit closure members; or
- arbitrary objects already in `/nix/store`.

Those bytes remain covered by the signed store realization graph. PCR 15
answers which exposed roots and manifests were activated, not which files have
ever existed on the machine.

## Keep configuration and secrets separate

Package configuration is evaluated from a typed, signed package interface and
materialized with the configuration generation. Secrets are supplied through
opaque references and systemd credentials. Permission to read one credential
does not imply access to another package's credentials or general secret
storage.

Do not place secret bytes in a package option intended for Nix evaluation, an
environment variable rendered into a unit, or a store-backed file. See [Manage
secrets on AOS](secrets.md) for the supported runtime paths.

## Verify the active sandbox

Start with APM's signed metadata and policy view:

```sh
apm info PACKAGE --system --permissions
apm policy PACKAGE --system
apm list --installed --system
```

After activation, inspect the exact target and workload units:

```sh
systemctl status aos-pkg-PACKAGE.target
systemctl cat PACKAGE.service
systemctl show PACKAGE.service \
  -p RootDirectory \
  -p RootImage \
  -p PrivateNetwork \
  -p PrivateUsers \
  -p CapabilityBoundingSet \
  -p DevicePolicy \
  -p SystemCallFilter
```

Check service logs and behavior in addition to static settings. A generated
sandbox can be internally consistent while the application is unhealthy or
while an intentionally granted privilege is broader than the deployment wants.

For remote attestation, use the public verifier described in [Use the AOS
command-line tools](cli.md#verify-runtime-attestation-evidence). A raw PCR value
without the CEL event log, quote identity, and signed policy is not sufficient
evidence.

## Know what the sandbox does not prove

The package sandbox does not prove:

- that the package publisher is trustworthy;
- that reviewed source produced the published bytes;
- that the program contains no vulnerabilities;
- that a package labeled `unconfined` is isolated;
- that a directly executed profile binary is confined; or
- that admission-time hashing provides dm-verity runtime integrity.

Use registry verification, provenance review, local permission policy,
runtime confinement, measured boot, monitoring, and recovery as distinct,
complementary controls.
