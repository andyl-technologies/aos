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
explicitly. If a dependency is missing from AOS, package it from source rather
than reaching into the host or importing nixpkgs.

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

## Bake the service into an image

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

Build the image:

```sh
git add systems/acme-server.nix
nix build .#acme-server-image-qcow2
```

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
candidate. `apm upgrade --system` upgrades the OS sysroot, not the runtime
package profile. Until a machine-wide runtime upgrade operation ships, roll a
new image containing the new package or use a release-specific, tested
remove-and-reconcile procedure. Do not present that workaround as an atomic
upgrade.

Verify the unit and application behavior before advancing more rollout
partitions. Registry channels are monotonic: stop a bad rollout and publish a
higher, corrected version rather than moving channel partitions backward.
