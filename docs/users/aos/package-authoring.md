# Package an application for AOS

An AOS package is a Nix derivation built from source with the AOS package set.
Adding an application normally has three parts:

1. define the package under `pkgs/`;
2. declare its typed package module when it contributes runtime behavior;
3. include it in a system variant or publish it to a registry.

This guide builds a small service package called `acme-health-agent`. The
example is deliberately self-contained so it can be evaluated and built
without a separate source repository.

Use [Review package security](../../maintainers/package-security.md) while
choosing dependencies and native ability requests. The corresponding
operator-visible boundary is documented in [Understand native package runtime
policy](package-runtime-policy.md).

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

Runtime dependencies normally identify installable packages and become available
to the retained module. For an internal artifact such as a bootstrap interpreter
embedded in generated scripts, use an explicit closure-only dependency:

```nix
runtimeDeps = [
  { package = stdenv.bash; closureOnly = true; }
  openssl
];
```

The builder still consumes that exact interpreter in the declared order, and
references in the output retain it in the Nix store closure. It does not become
an installable package dependency or a retained module binding. Ordinary runtime
libraries and commands remain ordinary dependency entries.

Contributors packaging a complex upstream build in the AOS repository should
also read [Package builder notes](../../engineering/build/package-builders.md)
for configure probes, hardening exceptions, parallelism, Bazel, and
fixed-output fetch rules.

A recipe `version` can carry its compatibility policy: `"^7.4.2"`, `"~7.4.2"`,
and `"=7.4.2"` all publish exact version `7.4.2`, with caret, tilde, or equal-version
requirements. Bare strict SemVer defaults to caret; other bare version schemes
remain exact-only. Use one optional operator and a full version, not a compound
range. The default is an authoring convention, not evidence that upstream follows
SemVer. Check the interface the package exposes: use `~` for a documented
patch-series guarantee, and `=` while a broader policy remains unverified.
Compatibility of an AOS-authored module also requires review of its options,
handlers, and effects; an upstream library ABI promise does not establish that
contract. Keep the rationale and any upstream policy link beside the recipe's
version declaration.

Keep the source URL variable exact when adding an operator:

```nix
{ mkDerivation, fetchurl, fakeHash, ... }: let
  version = "7.4.2";
in mkDerivation {
  pname = "acme-agent";
  version = "~${version}";
  src = fetchurl {
    urls = ["https://downloads.example.com/acme-agent-${version}.tar.gz"];
    hash = fakeHash;
  };
  # Dependencies and phases are declared normally.
}
```

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

## Declare the native package module

A recipe may publish a configuration module directory alongside its payload:

```nix
{ mkDerivation, service-interface, ... }:
mkDerivation {
  pname = "acme-health-agent";
  version = "1.0.0";
  module = ./acme-health-agent-module; # Contains module.nix.
  moduleDeps = [ service-interface ];
  # Sources, dependencies, and phases are declared normally.
}
```

The interface dependency is illustrative: select the package defining your
actual domain contract. Module dependencies are separate from build and runtime
library dependencies. A plain dependency inherits the package's generated
`package.versionRequirement`, so consumers need not repeat its declared range.
To override the range, use
`moduleDeps = [ { package = service-interface; packageVersion = "^7.0"; } ];`.
To pin immutable source identity, use
`moduleDeps = [ { package = service-interface; exact = true; } ];`; an equal-version
range can still select another source with that semantic version.
An optional recipe `osVersion = "^1.0";` checks the selected host OS release;
dependency resolution never selects or upgrades the OS. A payload-only package
does not need a module.

The module owns ordinary option declarations and configuration. It may expose
ability operations, select handlers, or configure effects through a domain
manager. Definitions in different files merge through the module fixed point.
The [runtime abilities guide](runtime-abilities.md) shows the complete interface,
service option, package configuration, handler composition, and execution path.

Use `module` and `moduleDeps` for native configuration. The builder rejects the
superseded `abilities` and `configModule` recipe fields.

## Generate and inspect package documentation

Descriptions and types belong beside `mkOption` declarations. The builder
projects options, operation schemas, and definition provenance from the same
module evaluation. Do not maintain a separate documentation attrset, service
catalog, or copy of the operation schema.

The derivation exposes `deployment` and `documentation` Nix values plus two
companion artifacts: `deploymentArtifact/deployment.json` and
`documentationArtifact/options.json`. The first retains payload and module
identities; the second is a native generated reference. Building either does
not activate the package.

After exporting `options.json`, inspect it without Nix or a running system:

```sh
aos docs runtime options.json
aos docs runtime options.json --format html --output package-reference.html
```

The same reader is available in Hub at `/-/runtime-abilities`. It links packages
to the operations they declare, handle, and configure. An evaluated
`aos.package.transaction` document instead shows the selected execution path.
See [runtime inspection](runtime-abilities.md#inspect-the-generated-reference-and-execution-path).

## Build and inspect the payload

Add source files to Git before using flake outputs, then use the repository
build entry point. `aos-dev` is on `PATH` inside the development shell:

```sh
aos-dev build package acme-health-agent --no-out-link
aos-dev build check effects --no-out-link
```

Use package-specific checks for program behavior, linking, protocols, and runtime
health. The generic effects check verifies the infrastructure with a small
fixture; it does not qualify every package or prove that a service is running.

## Integrate the service into a release image

The following is the existing image consumer workflow. Its integration with the
native runtime transaction path remains migration work; do not infer that
registering a package already switches its activation to the new machinery.

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

`bundle = true` includes the package payload, authenticated module, and signed
contract artifacts in the image. `preset = true` selects it in the initial
machine-wide desired package set. A preset package must also be bundled.

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
  --key-id release
```

`apr publish` evaluates the package's target inventory and publishes its
generated documentation, named outputs, and package contract from that exact
record. Keep the package's version, description, homepage, license, and
maintainers in its Nix `meta`; the registry command does not accept manual
copies of those fields for ordinary packages.

Create and upload a signed registry release using the workflow in
[Publish packages and releases](../registry/publishing.md). Once the consumer
has synchronized that registry, install the service by name:

```sh
apm update --system
apm install --system acme-health-agent --registry acme --dry-run
apm install --system acme-health-agent --registry acme
systemctl status acme-health-agent.service
```

For repeatable provisioning, include the package in a complete desired file
and apply it with `apm apply --system --from desired.toml`. See
[Manage packages](packages.md#apply-a-complete-package-set-from-a-file) for the
file's removal semantics.

## Ship a new version

Change the package version and source hash, build it, and run its checks. Then
publish the new store path and a new registry release. Packages in the AOS
repository declare their upstream through the
[update contract](../../engineering/package-maintenance/update-contract.md) so
maintainers can [update them with `aos maintain`](../../maintainers/package-upgrades.md). On a canary host, refresh
metadata and inspect the candidate:

```sh
apm update --system
apm list --upgradable --system
apm policy acme-health-agent --system
```

Preview and upgrade the installed runtime package:

```sh
apm upgrade --system acme-health-agent --dry-run
apm upgrade --system acme-health-agent
```

Verify the unit and application behavior before advancing more rollout
partitions. Registry channels are monotonic: stop a bad rollout and publish a
higher, corrected version rather than moving channel partitions backward.
