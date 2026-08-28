# Package an application for AOS

An AOS package is a Nix derivation built from source with the AOS package set.
Adding an application normally has three parts:

1. define the package under `pkgs/`;
2. expose its runtime interface when `apm` must activate it;
3. include it in a system variant or publish it to a registry.

This guide builds a small service package called `acme-health-agent`. The
example is deliberately self-contained so it can be evaluated and built
without a separate source repository.

## Define the package

Create `pkgs/acme/acme-health-agent.nix`:

```nix
{
  mkDerivation,
  coreutils,
  writeShellScriptBin,
}: let
  agent = writeShellScriptBin "acme-health-agent" ''
    set -eu

    while true; do
      printf 'acme-health-agent: healthy at %s\n' \
        "$(${coreutils}/bin/date --iso-8601=seconds)"
      ${coreutils}/bin/sleep 60
    done
  '';
in
mkDerivation {
  pname = "acme-health-agent";
  version = "1.0.0";
  src = null;

  runtimeDeps = [
    agent
    coreutils
  ];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        ln -s ${agent}/bin/acme-health-agent \
          "$out/bin/acme-health-agent"
      '';
    }
  ];

  expose = {
    units."acme-health-agent.service" = {
      description = "Acme host health agent";
      serviceConfig = {
        Type = "simple";
        ExecStart = "${agent}/bin/acme-health-agent";
        Restart = "on-failure";
        RestartSec = "5s";
      };
    };

    permissions = {
      network = "private";
      tcp-bind = [];
      capabilities = [];
      devices = [];
      host-paths = [];
      syscalls = "restricted";
    };
  };

  meta = {
    description = "Acme host health agent";
    license = "Apache-2.0";
  };
}
```

Package files are discovered recursively. Files and directories whose names
begin with `_`, and files named `default.nix`, are not published as packages.
The file above therefore creates `pkgs.acme-health-agent` and the flake output
`pkg-acme-health-agent`.

A discovered file that returns a callable package factory instead of a
derivation must be listed in `packageFactories` in `pkgs/default.nix`. Keep the
factory available through `pkgs.<name>` for its callers, but exclude it from
`packageNames`, the `pkg-*` flake outputs, and `packages.<system>.all`; Nix
cannot build a function. Use this explicit inventory because dynamically
probing every discovered value would evaluate unrelated packages and trigger
their IFDs during otherwise isolated builds.

The builder shell is POSIX `sh`. Keep phase scripts portable, and use explicit
AOS package paths in generated scripts. Do not use `/bin/bash`,
`/usr/bin/env`, host tools, or nixpkgs packages.

## Understand dependencies

Use the dependency field that matches why the package is needed:

| Field | Use |
| --- | --- |
| `buildDeps` | Compilers, build systems, generators, and other build-only tools |
| `runtimeDeps` | Libraries and commands needed when the package runs |
| `propagatedDeps` | Dependencies that downstream builds must inherit |

`mkDerivation` already supplies the wrapped compiler and bootstrap tools.
List application-specific build tools, libraries, and runtime commands
explicitly. Include tools that an upstream configure script probes before the
compile even when the build phases do not invoke them directly; for example,
declare Perl in `buildDeps` when configure rejects a missing Perl interpreter.
If a dependency is missing from AOS, package it from source rather than
reaching into the host or importing nixpkgs.

`mkDerivation` also enables the repository hardening profile. Keep that profile
unless an upstream representation is incompatible with one specific flag. For
example, code that deliberately uses a trailing one-element or zero-length
array as variable-length storage can trigger false `_FORTIFY_SOURCE` aborts
under `strictflexarrays3`. In that case, preserve fortify and the other
hardening checks while selecting the compatible flexible-array interpretation:

```nix
hardeningDisable = ["strictflexarrays3"];
hardeningEnable = ["strictflexarrays1"];
```

Document the upstream data layout and reproduce the actual build-time or
runtime abort before adding this exception. Do not disable all hardening to
work around one incompatible flag.

Use `$NIX_BUILD_CORES` for build systems whose parallel graph is safe. Keep a
legacy bootstrap stage serial when its upstream tool writes shared outputs from
multiple recursive branches. Set both the outer make job count and any separate
inner-build job variable to one because `make -j1` does not override a job count
that configure propagates explicitly. For example, IcedTea 2.6 must use
`make -j1 PARALLEL_JOBS=1` for its boot target because concurrent boot-javac
writers can corrupt compiler classes. Restore safe inner parallelism only after
the boot compiler is complete, and record the reproduced failure beside the
serialized command so a future upgrade can remove the restriction deliberately.
Do not rely on serialization alone for a boot compiler defect that also
reproduces with one job. OpenJDK 10's jrt filesystem can mutate an `ImageReader`
child list while javac traverses it, matching the failure recorded in
JDK-8299435, so snapshot the children before iteration in the OpenJDK 10
package. Also keep OpenJDK 11's bootstrap boundary at one job with the javac
server disabled because the snapshot does not make every jrt filesystem
operation safe for concurrent callers.

When an older HotSpot boot JVM defaults to AVX-512 and crashes in `libjvm`
during a large compiler batch, pass `-XX:UseAVX=2` through the upstream
boot-JDK JVM argument option. The glibc hardware-capability tunable only bounds
glibc's own routines; it does not constrain instructions generated by HotSpot.

For an upstream release, add `fetchurl` and `fakeHash` to the package function
arguments, keep `version` beside the source, and replace `src = null` with:

```nix
{fetchurl, fakeHash}: let
  version = "1.0.0";
in {
  src = fetchurl {
    urls = ["https://downloads.example.com/acme-agent-${version}.tar.gz"];
    hash = fakeHash;
  };
}
```

After adding the package file, obtain its hash with:

```sh
nix run . -- prefetch --package acme-health-agent
```

Replace `fakeHash` with the printed `sha256-...` value. Alternatively,
`--update` edits the package file; inspect that diff before committing. Keep
the version, source URLs, and hash together in the package file. Prefer more
than one trusted source URL when the upstream has a stable mirror.

For a Bazel package built with `mkBazelPackage`, leave `populateBCR` enabled
when the dependency graph uses Bazel modules. Set `populateBCR = false` when
the package explicitly disables Bzlmod and resolves only a `WORKSPACE` graph.
The optional empty-workspace synchronization otherwise downloads Bazel's
built-in repositories for platforms and toolchains the target does not use;
those bytes enlarge the fixed-output dependency closure and require needless
network policy exceptions. When a pinned Git repository has a commit-identical
official mirror on an already-used origin, prefer that mirror and verify the
exact commit before changing the recipe. Keep fork-only commits on their
canonical origin rather than substituting an unaffiliated mirror. Apply the
same rule to release archives: when one upstream owns multiple official
hostnames, verify that the pinned payloads are byte-identical and select the
hostname already used by the dependency closure instead of widening its
network-origin set.

When upstream commits a Cargo lockfile and generated Bazel crate repositories,
fetch that checked-in graph without setting `CARGO_BAZEL_REPIN`. Repinning asks
rules_rust to resolve compatible versions against the current registry index,
so the result can change even when the package source revision does not. Run a
repin only while intentionally updating the source and commit the regenerated
lock and repository definitions before calculating the new dependency hash.

## Expose the runtime interface

The `expose` attribute is the contract used by APM. It renders a separate
activation artifact containing units, firewall rules, configuration, and a
permission declaration. A package without `expose` can be used at image build
time, but it cannot be registered under `aos.packages` or activated as an APM
package.

The renderer creates a package target named:

```text
aos-pkg-<package-name>.target
```

Activating `acme-health-agent` enables
`aos-pkg-acme-health-agent.target`, which owns the service unit above. Units
marked `onlyManualStart = true` are installed but are not pulled into that
target.

Declare the narrowest permissions the service needs. `network = "private"`
gives the package an isolated network namespace. A service that must use the
host network needs `network = "host"` and the appropriate `tcp-bind` ports.
The package renderer rejects inconsistent permissions during evaluation.

## Add an on-host configuration module

Use `configModule` when host policy must set typed package options at runtime.
Keep the module in a local directory containing `module.nix`; it receives
`lib`, `config`, and a resolver-supplied `outputs` attrset. Declare every
runtime output that the module interpolates by name:

```nix
configModule = {
  src = ./config-module;
  dependencies = {
    bash = bash;
  };
  declares = ["acmeHealth.command"];
  ownsRoots = [{root = "acmeHealth";}];
};
```

The module refers to that output without importing a package set:

```nix
{lib, outputs, ...}: {
  options.acmeHealth.command = lib.mkOption {
    type = lib.types.str;
    default = "${outputs.dependencies.bash}/bin/bash";
  };
}
```

`mkDerivation` exposes the resolved map as `configModuleDependencies` without
copying store paths into the config-only output. Publication must bind the same
names to their exact runtime outputs:

```sh
apr publish "$STORE_PATH" \
  --config-module "$CONFIG_MODULE_PATH" \
  --config-base-lib "$BASE_LIB_PATH" \
  --config-dependency "bash=$BASH_PATH" \
  --registry acme \
  --key-id initial
```

Each dependency must be a direct reference of the published runtime output.
The registry signs the name-to-path map, and on-host evaluation injects that
authenticated map as plain strings. It never exposes ambient packages or
instantiates a derivation.

## Build and inspect the package

Add the new file to Git before using its flake output; flakes evaluate the
tracked source tree:

```sh
git add pkgs/acme/acme-health-agent.nix
nix build .#pkg-acme-health-agent
```

Inspect the payload and rendered activation manifest:

```sh
find result -maxdepth 3 -type f -o -type l
nix-build -A pkgs.acme-health-agent.expose -o result-expose
sed -n '1,240p' result-expose/manifest.json
```

Run repository checks before publishing:

```sh
nix run . -- lint
nix run . -- test eval
nix build .#pkg-acme-health-agent
```

Add package-specific checks under the derivation's `checks` attribute when a
version command, library link, protocol response, or VM behavior can be tested
directly. A successful build proves that the output was produced; it does not
by itself prove that the service is healthy.

## Integrate the service into a release image

This is a release-maintainer workflow. Users of a published AOS image should
install the package from a registry with `apm` instead. See
[Build and customize release images](../../maintainers/system-images.md) for
the image build and validation process.

Register the package in a system variant:

```nix
# systems/acme-server.nix
{pkgs, ...}: {
  imports = [./server.nix];

  aos.packages.acme-health-agent = {
    package = pkgs.acme-health-agent;
    bundle = true;
    preset = true;
  };
}
```

`bundle = true` includes the package and its activation artifact in the image.
`preset = true` enables its package target when AOS seeds the initial system
package profile. A preset package must also be bundled.

Build and validate the image as described in the release-image maintainer
guide linked above.

After boot, inspect both the APM state and the service:

```sh
apm list --installed --system
systemctl status acme-health-agent.service
journalctl -u acme-health-agent.service -b
```

## Publish and install the package

Build the store path, then publish it from the registry's authoring clone:

```sh
STORE_PATH="$(nix build .#pkg-acme-health-agent \
  --no-link --print-out-paths)"

apr publish "$STORE_PATH" \
  --registry acme \
  --description "Acme host health agent" \
  --license Apache-2.0 \
  --maintainer packages@example.com \
  --key-id release
```

Create and upload a signed registry release using the workflow in
[Publish packages and releases](../registry/publishing.md). Once the consumer
has synchronized that registry, declare the service in a machine-wide desired
file:

```toml
packages = ["acme-health-agent"]
```

Preview and reconcile the complete desired set:

```sh
apm update --system
apm install --system --from ./desired.toml --dry-run
apm install --system --from ./desired.toml --yes
systemctl status acme-health-agent.service
```

The file is authoritative: packages omitted from it are removed during
reconciliation. `apm install PACKAGE --system` is instead the OS-sysroot
install path and rejects an ordinary application package.

## Ship a new version

Change the package version and source hash, build it, and run its checks. Then
publish the new store path and a new registry release. On a canary host, refresh
metadata and inspect the candidate:

```sh
apm update --system
apm list --upgradable --system
apm policy acme-health-agent --system
```

The current machine-wide desired-package reconciler installs and removes roots,
but does not replace an already-present package with a newer registry
candidate. `apm upgrade --system` stages an A/B OS image, not the runtime
package profile. Until a machine-wide runtime upgrade operation ships, roll a
new image containing the new package or use a release-specific, tested
remove-and-reconcile procedure. Do not present that workaround as an atomic
upgrade.

Verify the unit and application behavior before advancing more rollout
partitions. Registry channels are monotonic: stop a bad rollout and publish a
higher, corrected version rather than moving channel partitions backward.
