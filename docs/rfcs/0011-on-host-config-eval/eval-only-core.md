# RFC-0011 — the eval-only core

The on-host evaluator consumes authenticated configuration inputs without
realizing derivations. It produces a canonical manifest;
the activation path assembles already-authenticated bytes into a configuration
generation and switches it atomically.

This document describes the implemented boundary. The detailed schemas and
failure contracts live in [build-spec.md](build-spec.md), and executable gates
are indexed in [acceptance-criteria.md](acceptance-criteria.md).

## Frozen image input

Every image carries an ABI-pinned `base-lib` containing:

- the module engine and the image's configuration-only module set;
- frozen package records whose string coercions name already-built store paths;
- image-fixed artifact paths captured during the image build;
- the system-root ownership and contribution surface; and
- an `evalHostConfig` entry point for operator, facts, and authenticated package
  modules.

The frozen package records expose no builders. A stage-2 evaluation therefore
cannot enter the source build graph, use import-from-derivation, or consult an
ambient package set. The base library and stock evaluator are part of the
verified image root and are recorded in each configuration manifest.

## Pure producer

`apm __eval` invokes the AOS-built `nix-instantiate` with explicit path
allowlisting, no ambient Nix search path, no import-from-derivation, and the
service's time and memory limits.

Evaluation returns:

- `aos.config-manifest/v1`, containing `/etc`, units, job-script text, users,
  desired packages, credential references, and authenticated input pins.

Missing providers, undefined options, conflicting unique values, failed
assertions, resource exhaustion, and opaque evaluator failures are distinct
typed outcomes. A terminal failure does not advance the generation pointer or
change the live `/etc` transaction.

## Builder-free runtime artifacts

Runtime-variable configuration is represented as manifest data:

- text, symlink, and authenticated store-symlink `/etc` entries;
- unit files plus inline job-script bodies;
- certificate bundles assembled from ordered certificate-only text and pinned
  store-file inputs; and
- opaque `secretRef` credential handles whose plaintext never enters Nix or a
  generation manifest.

Image-fixed outputs may still be derivations during the image build. When an
operator changes the corresponding setting on-host, the module emits a pure
runtime representation instead of invoking that builder.

## Imperative consumer

The materializer validates ownership, store pins, paths, modes, and artifact
schemas before writing a candidate generation. It builds the deterministic
EROFS configuration lower, rewrites job-script placeholders to generation-local
paths, compiles the unit graph, and prepares the service reconciliation plan.

Activation then:

1. realizes and validates every required authenticated package output;
2. re-projects a soft-failed package set to a dependency-closed degraded
   manifest when allowed;
3. constructs the candidate `/etc` lower and pre-swap unit plan;
4. swaps the `/etc` lower;
5. publishes opaque credentials and reconciles their consumers;
6. emits and verifies the generation attestation;
7. commits the `current` generation pointer; and
8. publishes the durable activation record.

Failures before the swap leave the previous generation fully live. Post-swap
ordinary unit-reconciliation failures may be recorded as degraded and return
the documented non-zero status. Credential or attestation failures enter the
rescue path and never commit the generation pointer or publish a stale complete
proof.

## Boot and generation integration

The initrd restores the current retained generation's EROFS configuration lower
before mounting `/etc`. The running image contributes the immutable base lower,
while `/var/etc` is limited to explicitly persistent host identity material.

Configuration and image generations are independent axes. Configuration
generations retain their exact host input, normalized facts, authenticated
config outputs, evaluator, and ABI-pinned base library. Image transitions use
an A/B root and UKI layout with sd-boot counting; first boot re-evaluates the
retained configuration intent against the new image before blessing it.

## Executable gates

The core is covered by the pure config-eval, materialization, provenance,
stock evaluation, retained-input GC, and two-axis generation
checks. Fleet gates exercise literal metadata `host.nix` activation, no-metadata
image defaults, conflict no-op behavior, rollback and reboot retention, durable
A/B fallback, measured/verified boot, and lifecycle idempotency.

The public images and production key-custody workflow remain release concerns;
they are not missing evaluator or activation primitives.
