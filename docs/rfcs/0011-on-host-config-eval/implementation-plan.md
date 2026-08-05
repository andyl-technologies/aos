# RFC-0011 implementation plan

Status: **implementation complete; validation gates defined below**.

This file records implementation state, not the result of a particular CI or
local run. A checked item means that the production path and its regression
coverage exist in the tree. The exact release gates are listed at the end and
must pass before merge.

P2 `aos-nix` is the only production evaluator. Stock Nix remains solely as the
differential oracle used by `checks.config-parity-p2`; it is not a runtime
fallback. The earlier P1 stock-evaluator milestones are therefore recorded
below by the production behavior that superseded them.

## Characterization and pure rendering

- [x] Characterize every discovered system variant with
      `checks.system-characterization`, backed by
      `lib/testing/system-characterization.nix` and committed fixtures under
      `tests/fixtures/system-characterization-goldens/`.
- [x] Keep the flat renderer as a deterministic migration oracle in
      `crates/aos-package/tests/golden_config_artifact.rs` and
      `checks.config-parity`.
- [x] Render systemd units and job scripts as pure manifest data; materialize
      builder and runtime outputs from the same `aos.config-manifest/v1`
      contract. Evidence: `checks.systemd-lib`, `checks.systemd-generate`,
      `checks.config-manifest`, and `checks.config-materialize`.
- [x] Pin boot and substrate outcomes in the existing
      `checks.fleet.install-from-image`, `checks.fleet.measured-boot`, and
      `checks.fleet.apm-system-upgrade` suites.

## Package configuration and module authority

- [x] Publish a separate authenticated package `config` output, carry it in
      registry metadata/store realization, and enforce the multi-output
      feature gate and references-as-strings discipline.
- [x] Evaluate the former expose surface as typed module options, including
      units, firewall/kernel requests, artifacts, permissions, certificates,
      and credential declarations. Evidence: `checks.package-expose` and
      `checks.config-parity`.
- [x] Derive `declares`/`requires` metadata and provider edges instead of using
      a hand-authored `expose.requires` list.
- [x] Mount private options below each package root and resolve shared roots
      through authenticated `SystemRoots`, with one owner per resolved system.
- [x] Enforce virtual-root alternatives, priority-75 operator definitions,
      typed `host.facts.*`, unique shared scalars, and foreign-enable/
      contribution-surface restrictions from resolver-assigned provenance.
      Evidence: `checks.eval`, `checks.module-enforcement`, and
      `checks.rfc-0011-provenance`.

## Native resolution and evaluation

- [x] Resolve missing providers to a bounded fixpoint with structured causal
      errors for missing, ambiguous, incompatible, cyclic, or conflicting
      roots.
- [x] Record and enforce `module_abi` and each config module's compatibility
      band before manifest publication.
- [x] Run `aos-eval.service` after network readiness and before graph
      compilation as a pure, allowlisted, no-build native evaluation.
- [x] Enforce native step, heap, and call-depth limits plus the systemd
      defense-in-depth sandbox (`MemoryMax`, `MemoryHigh`, `TasksMax`, timeout,
      read-only inputs, `ProtectSystem=strict`, and syscall restrictions).
- [x] Reject statically evident divergence across the strictly demanded import
      tree before execution.
- [x] Return a first-class option read/write graph and use it for resolver DAG
      edges and exact provider discovery.
- [x] Persist dependency-traced evaluation state and perform early cutoff for
      unaffected imports/roots after a small host change.
      Evidence for this section is `checks.config-eval` and
      `checks.config-parity-p2` plus the native evaluator's Rust tests.

## Two-axis generations and activation

- [x] Separate durable A/B image generations from numbered configuration
      generations under `/var/lib/profiles/image` and
      `/var/lib/profiles/system`.
- [x] Bind every config record to its parent image, pinned ABI, manifest hash,
      exact config modules/packages, `host.nix`, facts, base library, and
      evaluator.
- [x] Materialize the dependency-closed manifest as a generation-local EROFS
      `/etc` lower, then run the atomic activation transaction.
- [x] Keep image upgrades image-first: stage the inactive slot, reboot under
      boot counting, re-evaluate against the booted image, then activate.
      Config-only switches do not reboot.
- [x] Reactivate same-ABI rollback targets directly. Re-evaluate cross-ABI
      targets from their retained authenticated inputs and create a fresh
      config generation.
- [x] Refuse exhausted counted UKIs and use durable `bootctl set-default`
      image selection rather than lexical filename ordering.
- [x] Pin config outputs in `gen-N/cfg/`, evaluator inputs in
      `gen-N/cfgsrc/`, and required prior base libraries below image-generation
      roots.
- [x] Implement `apm clean --system --generations --keep N` for both the
      system-package and config profiles. It preserves the latest window plus
      each current generation, serializes config pruning with activation,
      journals state-first deletion, reconciles base-library roots, and releases
      pruned `cfg/`/`cfgsrc/` roots for `apm gc`.
      Evidence: `checks.rfc-0011-cfgsrc-gc`,
      `checks.fleet.rfc-0011-two-axis-gen`,
      `checks.fleet.rfc-0011-image-rollback`, and
      `checks.fleet.rfc-0011-gc-roots`.

## Provisioning and orchestration

- [x] Build and ship `systemd-repart`/fdisk support, convention repart
      definitions, root-first pending/committed markers, lifecycle guards, and
      LUKS/swap ordering on `systemd-repart.service`; the retired growfs,
      GPT-relocate, Ignition, and Butane paths are absent.
- [x] Implement native `aos metadata detect`, `fetch`, and exact-byte
      authorization for offline config drives and AWS, GCP, Azure, OpenStack,
      and DigitalOcean metadata services.
- [x] Evaluate only the typed provisioning projection in the initrd, validate
      and render it in Rust, commit storage once, retain audit/recovery input,
      and dry-run later boots for drift without reopening mutation.
- [x] Parse the supported NoCloud network subset without a general unsafe YAML
      dependency and seed DHCP-less OpenStack/DigitalOcean networking before
      stage-2 fetch.
- [x] Render normalized `facts.json` only through typed `host.facts.*`; retain
      it as a hashed generation input. No unverified facts write the live
      hostname or authorized keys.
- [x] Replace the monolithic install unit with the generated
      `aos-pkg-fetch@`/`aos-pkg-install@` graph, fetch/render/config targets,
      `aos-graph-compile`, and a single `aos-activate` commit.
- [x] Use `Wants=` and bounded retry for package fetch degradation while
      reserving hard dependencies for substrate edges. Re-project and re-hash
      the dependency-closed manifest and record exact drop reasons.
      Evidence: `checks.fleet.provisioning-boot`,
      `checks.fleet.apm-desired-sequencing`, and
      `checks.fleet.rfc-0011-degraded-boot`.

## Image/host boundary, trust, and secrets

- [x] Keep production server/edge images capability-only and select runtime
      server/edge roles from authenticated `host.nix`; feature tools stay out
      of the interactive package set while their referenced store closure is
      manifest-owned and pinned. Evidence:
      `checks.fleet.rfc-0011-runtime-role`.
- [x] Move runtime hostname, networking, users, SSH/chrony, firewall, audit,
      journald, PAM, monitoring, PKI, registry routing, units, and desired
      packages into manifest materialization while retaining kernel/initrd,
      verity, measured boot, ABI, and initial trust as image capabilities.
- [x] Remove production passwordless root autologin and keep recovery access an
      explicit image capability.
- [x] Support platform trust by default and exact-byte signed `host.nix` with
      measured trust anchors and optional operator delegation.
- [x] Enforce authenticated contribution grants rather than module-controlled
      `_file` provenance.
- [x] Anchor the running evaluator/base-library root to the dm-verity image and
      measured kernel command line. Evidence: `checks.systemd-verity`,
      `checks.fleet.measured-boot`, and `checks.fleet.package-attestation-quote`.
- [x] Keep `secretRef` opaque in evaluated state. Resolve every reference into
      process-local pending bytes, publish all credential files at the
      post-`/etc`-swap barrier before any consumer reconciliation, prune files
      for removed handles in the same transaction, validate TPM2 sources in the
      fully composed view before the pre-swap reconcile, then restart only
      previously active consumers in systemd dependency order. Reconciliation
      attempts every consumer and reports a
      degraded switch if any job fails. Resolution failure leaves credentials
      and the live generation unchanged; publication failure restores prior
      credential targets and refuses the config pointer and activation proof.
      Early boot resolves or rejects interrupted credential journals before admitting the
      retained configuration lower and its consumers. Evidence:
      `checks.systemd-credentials` and `checks.fleet.rfc-0011-secret-ref`.
- [x] Produce `aos.gen-attestation/v1`, make crash retries idempotent by durable
      activation identity, and give every later activation or rollback a fresh
      CEL event, PCR 15 extension, and PCR 7/11/12/15 quote over the exact
      manifest and authenticated inputs. The public verifier checks an
      identity-pinned quote, signed release/store evidence, host trust, and
      optional re-derivation. Boot blessing requires the matching activation
      and generation records.

## Operability and compatibility

- [x] Implement `apm switch --dry-run`, JSON output, `--diff-against current`,
      `--diff-against gen-N`, and persisted `gen-N/manifest.json`.
- [x] Surface stable structured evaluation classes and resource failures to
      APM and the journal without changing the live generation.
- [x] Retain the flat renderer only as a non-production compatibility oracle;
      verify byte parity with `checks.config-parity`.
- [x] Cover conflict no-op, dry-run/realized equivalence, same-ABI rollback,
      cross-ABI re-evaluation, incompatible-firstboot fail-closed behavior,
      degraded activation, secrets, role selection, A/B rollback, and GC-root
      retention with real fleet tests.

## Required merge gates

These are commands to run; this document does not claim their current result.

```sh
nix-build -A checks.rfc-0011-all --no-out-link
nix-build -A checks.fleet.rfc-0011-all --no-out-link
```

`checks.rfc-0011-all` is the complete non-KVM gate: it builds `pkgs.aos` and
the evaluation, lint, module, package configuration, characterization,
materialization, parity, provenance, GC-root, and systemd contract checks.

`checks.fleet.rfc-0011-all` is assembled in `default.nix` from every discovered
`tests/fleet/rfc-0011-*.nix` plus `apm-desired-sequencing`,
`apm-system-activation-fail`, `apm-system-upgrade`, `install-from-image`,
`measured-boot`, `package-attestation-quote`, and `provisioning-boot`. It
therefore includes newly added RFC-prefixed fleet tests without a second manual
list.
