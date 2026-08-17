# RFC-0011 acceptance criteria

Status: **implementation complete; every gate below is required before merge**.

A checked criterion means the implementation and named regression gate exist.
It does not assert that a particular working-tree revision has already passed
the gate. Test results belong in CI and the pull request, not in this durable
specification.

## Pure data contract and package surface

- [x] Every discovered system preserves contextual Nix references for its
      rendered outputs, and the realized systemd tree exactly matches the pure
      manifest inventory without committed generated snapshots.
  - Gates: `checks.system-structure`, `checks.systemd-generate`, and
    `checks.config-manifest`.
- [x] Builder and runtime paths consume the same strict
      `aos.config-manifest/v1` shape, including exact base-library, evaluator,
      module, host, and fact inputs.
  - Gates: `checks.config-manifest` and `checks.config-materialize`.
- [x] Package configuration is a separate authenticated output with typed
      expose options, declared/provided/required roots, feature negotiation,
      realization metadata, and references-as-strings enforcement.
  - Gates: `checks.package-expose`, `checks.config-parity`, and the
    `aos-package` Rust suite built by `pkgs.aos`.

## Module authority and provenance

- [x] Private package roots cannot cross-write; shared roots have one selected
      authenticated owner per system and support explicit virtual-root
      alternatives.
- [x] Operator definitions use the priority-75 provenance tier without subtree
      wrapping; equal shared scalar conflicts fail instead of silently winning.
- [x] Only typed `host.facts.*` supplies facts. Ambient evaluator inputs are
      unavailable in pure mode.
- [x] Foreign `enable` writes and out-of-grant shared contributions fail, while
      an owner may enable its declared subfeatures.
- [x] Authority is derived from authenticated fetch/selection metadata, never
      from a module's self-reported `_file` value.
  - Gates for this section: `checks.eval`, `checks.module-enforcement`, and
    `checks.config-provenance`.

## Native evaluator and resolver

- [x] Production evaluation is in-process `aos-nix`; there is no stock-Nix
      runtime fallback.
- [x] Missing providers, ambiguity, incompatibility, conflicts, unsatisfiable
      cycles, non-convergence, and resource exhaustion produce stable structured
      errors before activation.
- [x] Module ABI compatibility is checked before manifest publication and the
      chosen ABI is retained in each config-generation record.
- [x] Evaluation is pure and allowlisted, performs no builds, enforces step,
      heap, and call-depth limits, and rejects statically evident divergence in
      the strictly demanded import tree.
- [x] The evaluator returns a first-class option access graph. Persistent,
      dependency-traced cache entries cut off unaffected work while a changed
      host dependency is recomputed; warm and cold results remain identical.
- [x] `aos-eval.service` is ordered after network readiness and before graph
      compilation and applies its documented cgroup, filesystem, task, timeout,
      and syscall restrictions.
  - Gates: `checks.config-eval`, `checks.config-parity-p2`, and the native
    evaluator Rust tests included in `pkgs.aos`.
  - `checks.config-parity-p2` is the stock/native differential oracle; stock
    evaluation is test-only.

## Graph, degradation, and atomic activation

- [x] The compiler writes per-package fetch/render drop-ins and target wants,
      reloads systemd once, awaits `aos-activate.service` while it drives the
      fetch/render wings, and publishes `aos-config.target` after activation.
- [x] Package fetch edges use `Wants=` with bounded retry. Required boot/storage
      edges remain hard dependencies.
- [x] A soft-failed package and its dependents are removed by dependency-closed
      re-projection; independent packages continue. The projected manifest is
      re-hashed and the exact drop set is recorded.
- [x] `/etc` is built as a generation-local EROFS lower and switched atomically.
      Pre-swap errors preserve the previous live generation. Post-swap
      completion requires credential publication and consumer reconciliation,
      generation attestation, the current-generation pointer, and the exact
      activation record, in that order.
- [x] Recovery does not infer completion from the `/etc` live marker. An
      interrupted transaction that crossed the swap without completing its
      later barriers remains fail-closed for rescue diagnostics.
  - Gates: `checks.config-materialize`,
    `checks.fleet.apm-desired-sequencing`,
    `checks.fleet.config-degraded-boot`, and
    `checks.fleet.on-host-config-eval`.

## Provisioning and metadata

- [x] `systemd-repart` owns first-boot partition creation/growth with root-first
      pending/committed markers, typed validation, lifecycle guards, LUKS/swap
      ordering, durable audit data, and later-boot drift-only dry runs.
- [x] `aos metadata` supports the advertised config-drive and cloud transports,
      request bounds, exact-byte platform/signed authorization, and safe parsing
      of the consumed NoCloud subset.
- [x] DHCP-less OpenStack/DigitalOcean metadata can seed a minimal networkd
      route before stage-2 registry access.
- [x] Facts are normalized into a content-addressed `facts.json` and typed
      `host.facts.*` input. Unverified fact data cannot imperatively write
      hostname or authorized keys.
- [x] Ignition, Butane, the retired growfs/GPT-relocate units, and the
      monolithic package installer are absent from production.
  - Gates: `checks.fleet.provisioning-boot`,
    `checks.fleet.install-from-image`, and `checks.eval`.

## Image and configuration generations

- [x] Image and configuration generations have independent state and pointers.
      Config records bind the image parent, ABI, manifest, authenticated module
      identities, host input, fact input, base library, and evaluator.
- [x] A config-only switch does not reboot or change image identity. An image
      upgrade stages the inactive A/B slot, selects a counted UKI durably,
      reboots, and evaluates a fresh compatible configuration after boot.
- [x] Same-ABI rollback re-runs activation from retained output. Cross-ABI
      rollback retains exact inputs, re-evaluates against the running base
      library, and creates a fresh child generation.
- [x] An incompatible config module during first boot leaves the prior
      configuration and manifest live while management access remains available.
- [x] Exhausted counted UKIs cannot be selected or blessed. Boot blessing
      requires matching image, activation, generation-attestation, and measured
      evidence.
  - Gates: `checks.fleet.config-image-generation-axes`,
    `checks.fleet.system-image-rollback`, and
    `checks.fleet.measured-boot`.

## Retention and garbage collection

- [x] `gen-N/cfg/` pins realized configuration outputs and `gen-N/cfgsrc/`
      pins exact modules, `host.nix`, facts, base-library, and evaluator inputs.
- [x] Image-generation roots preserve the exact A/B-resident generation
      numbers, every exact image parent named by a retained config generation,
      and the newest exact prior generation with a distinct ABI.
- [x] `apm clean --system --generations --keep N` prunes ordinary system-package
      and config generations independently, retaining each latest `N` window
      plus each current generation.
- [x] Config pruning holds the activation switch lock, writes a versioned
      durable journal, publishes reduced state before removing directories,
      completes an interrupted prune before a later activation, reconciles
      base-library roots, and treats runtime-upper cleanup as best effort.
- [x] After pruning and `apm gc`, retained outputs and cross-ABI inputs survive,
      pruned-only roots are collectable, and retained rollback still materializes
      the expected `/etc`.
  - Gates: `checks.config-source-gc` and
    `checks.fleet.config-generation-gc-roots`.

## Image/host policy boundary

- [x] Production server and edge variants carry boot, storage, trust,
      evaluation, activation, and recovery capability without preselecting a
      workload/debug runtime role.
- [x] Authenticated `host.nix` selects runtime roles, desired packages,
      hostname/networking, accounts/access, SSH/chrony, firewall/audit/journal,
      PAM/monitoring, runtime PKI, registry routing, files, and services.
- [x] Absolute store references contributed by runtime roles are included in
      manifest ownership and roots even when their tools are absent from the
      login package set.
- [x] Kernel/initrd, immutable root, dm-verity, measured boot, module ABI, and
      initial trust anchors remain image-owned.
  - Gates: `checks.fleet.runtime-config-role` and
    `checks.system-structure`.

## Secrets and attestation

- [x] Evaluated configuration accepts opaque `secretRef` handles only; manifest
      and retained generation artifacts never contain resolved plaintext.
- [x] Every reference is checked against authenticated package declarations.
      Resolution stages bytes in process memory; no credential file changes
      before the atomic `/etc` swap succeeds.
- [x] Each mode-`0600` credential target publishes, or is pruned when its
      authenticated `secretRef` disappears, under one durable,
      rollback-capable transaction. Package-authored TPM2 sources are checked
      in the fully composed staged view before any live unit is stopped. Only
      consumers active before the transaction restart, in deterministic
      systemd dependency order; one failed job does not suppress later jobs.
      Resolution or publication failure preserves prior targets and consumer
      state and refuses the config pointer and activation proof.
- [x] Early boot recovers or rejects every interrupted credential journal before
      admitting the retained configuration lower and its consumers.
- [x] `aos.gen-attestation/v1` binds activation and generation IDs, manifest
      hash, image parent, ABI, host/facts/modules, trust mode, and
      signer/release evidence. Same-generation rollback refreshes activation
      proof, CEL identity, and quote evidence.
- [x] PCR 15 extension is crash-idempotent and the quote covers PCR 7/11/12/15;
      verification replays the prior validated CEL prefix and rejects an
      embedded quote that differs from the identity-pinned bundle. The public
      verifier reconstructs signed release membership and realization rather
      than trusting host-reported fields.
  - Gates: `checks.systemd-credentials`,
    `checks.fleet.config-secret-reference`,
    `checks.fleet.measured-boot`, and
    `checks.fleet.package-attestation-quote`.

## Operator surface

- [x] `apm switch --dry-run` and JSON mode report `/etc`, unit, fetch, and
      resolution changes without mutation; `--diff-against` accepts `current`,
      `gen-N`, or an explicit manifest path.
- [x] Successful activation persists `gen-N/manifest.json`, activation state,
      generation attestation, and the exact content-addressed generation record.
- [x] Conflict, assertion, provider, ABI, resource, and convergence failures
      have legible stable classifications and leave the old generation live.
- [x] User documentation describes runtime host activation, A/B rollback,
      secrets, pruning, and remaining early-preview/product-distribution limits
      without describing implemented paths as absent.
  - Gates: `checks.config-eval`, `checks.fleet.on-host-config-eval`, and the
    documentation review in the RFC pull request.

## Aggregate release gates

Run all of the following on a Linux builder. These targets are definitions of
acceptance, not a claim about the current run result:

```sh
nix-build -A checks.runtime-config-all --no-out-link
nix-build -A checks.fleet.runtime-config-all --no-out-link
```

`checks.runtime-config-all` is the complete non-KVM gate: it builds `pkgs.aos` and
the evaluation, lint, module, package configuration, focused system-structure,
materialization, parity, provenance, GC-root, and systemd contract checks.

`default.nix` discovers every regular `tests/fleet/*.nix` file. The fleet
aggregate selects an explicit capability-based list of the configuration,
activation, image-transition, measured-boot, attestation, and provisioning
checks that collectively define acceptance.
