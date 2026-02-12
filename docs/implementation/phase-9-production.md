# Phase 9: Cleanup and Production Readiness

**Plan Phase:** 12 (Cleanup + Production)

## Objective

Final integration: remove all Guix-era files, update `.gitignore`, run the full test suite against all image variants, verify the end-to-end pipeline (build -> test -> image -> deploy), and confirm AOS is production-ready on the Nix infrastructure.

## Prerequisites

- Phase 1-8 complete: All packages build, modules evaluate, images boot, tests pass, CLI works, deployment pipeline functional
- All documentation updated (Phase 11 in the plan covers docs separately)

## Deliverables

- Clean repository with no Guix artifacts
- Updated `.gitignore` for Nix-only workflow
- All four image variants (base, server, k8s-worker, k8s-control-plane) building and booting
- Full test suite passing (`aos test` -- eval, build, vm, fleet)
- Deployment pipeline verified (bundle, sign, upload, fleet update)
- Production checklist completed

## Detailed Task Checklist

### 9.1 Remove All Guix Files

- [ ] Delete `channel/` -- all `.scm` files (packages, systems, services, images, tests, config, TOML parser)
- [ ] Delete `docker/` -- Dockerfile, docker-compose*.yml, entrypoint.sh
- [ ] Delete `build/` -- build-image.sh, backfill-hashes.sh, extract-sources.scm, apply-hashes.sh
- [ ] Delete `config/` -- all TOML files (values absorbed into Nix modules)
- [ ] Delete `images/*.toml` -- image manifests (replaced by Nix expressions)
- [ ] Delete `scripts/guix` -- Guix wrapper script
- [ ] Delete `scripts/qemu-run.sh` -- old QEMU testing (replaced by `aos test vm`)
- [ ] Delete `.guix-channel` -- channel descriptor
- [ ] Delete `.env` -- Docker Compose env
- [ ] Delete `examples/` -- Guix-era examples

### 9.2 Update .gitignore

- [ ] Remove Docker-specific entries
- [ ] Remove Guix-specific entries (`/gnu/`, `.guix-profile`, etc.)
- [ ] Add Nix-specific entries:
  - [ ] `result` and `result-*` (nix-build symlinks)
  - [ ] `output/` (built images)
  - [ ] `.direnv/` (if using direnv)
- [ ] Add Rust-specific entries:
  - [ ] `cli/target/`
- [ ] Keep `kernel-config/` entry removed (configs moved to `pkgs/kernel/config/`)

### 9.3 Final Integration Test

- [ ] Build all packages: `aos build --all`
- [ ] Evaluate all system variants: `aos system eval base && aos system eval server && aos system eval k8s-worker && aos system eval k8s-control-plane`
- [ ] Build all images: `aos system image base && aos system image server && aos system image k8s-worker && aos system image k8s-control-plane`
- [ ] Run full test suite: `aos test`
  - [ ] Eval layer passes
  - [ ] Build layer passes
  - [ ] VM layer passes (all 6 suites: boot, immutability, security, networking, kubernetes, update)
  - [ ] Fleet layer passes (k8s-cluster, rolling-update)
- [ ] Verify CLI: `aos --help`, `aos describe`, `aos completions bash`
- [ ] Verify deployment pipeline: `deploy/bundle.nix` and `deploy/sign.nix` produce signed bundles

### 9.4 Production Hardening Verification

- [ ] Security:
  - [ ] SELinux is enforcing on all image variants
  - [ ] All files in the golden image have correct SELinux labels (no `unlabeled_t`)
  - [ ] sysctl hardening values set (kptr_restrict=2, dmesg_restrict=1, ptrace_scope=1, etc.)
  - [ ] nftables firewall active with role-appropriate rules
  - [ ] SSH hardened (key-only auth, modern ciphers, restricted forwarding)
  - [ ] No password-based root login
  - [ ] Boot editor disabled in systemd-boot (`editor no`)
  - [ ] Kernel hardening: KASLR, KPTI, stack protector, FORTIFY_SOURCE
- [ ] Immutability:
  - [ ] Root filesystem is ext4 mounted read-only
  - [ ] `/nix/store` is read-only at runtime
  - [ ] `/var` is writable on ZFS (only mutable area)
  - [ ] `/etc` overlay works correctly (base from ext4, changes on ZFS)
  - [ ] No writes to root during normal operation
- [ ] Deployment:
  - [ ] Update bundles contain only delta store paths
  - [ ] Bundle signatures verify correctly
  - [ ] Boot counting protocol works (3 tries, then fallback)
  - [ ] Health check service runs and marks successful boots
  - [ ] GC correctly identifies and removes unreferenced store paths
  - [ ] Update and GC are mutually exclusive (locking)

### 9.5 Performance Verification

- [ ] System evaluation completes in <1 second (all four variants)
- [ ] Package build uses Nix caching effectively (no unnecessary rebuilds)
- [ ] Image build completes in reasonable time with KVM
- [ ] Boot time: system reaches multi-user.target within 60 seconds
- [ ] Store closure sizes are within documented bounds:
  - [ ] Base: <1 GiB
  - [ ] Server: <1.5 GiB
  - [ ] K8s worker: <2 GiB
  - [ ] K8s control plane: <2.5 GiB

### 9.6 Documentation Alignment

- [ ] Verify all `docs/` files reference Nix (not Guix)
- [ ] Verify all file paths in docs match actual repository structure
- [ ] Verify all commands in docs work (`aos build`, `nix-build -A`, etc.)
- [ ] Verify version numbers in docs match `pkgs/versions.nix`

## Acceptance Criteria

1. Repository contains no Guix files (channel/, docker/, build/, config/, .guix-channel, .env)
2. All four image variants build and boot successfully
3. Full test suite passes: `aos test` (eval + build + vm + fleet)
4. `aos` CLI works for all subcommands
5. Deployment pipeline produces signed update bundles
6. SELinux is enforcing with no critical AVC denials
7. All security hardening measures are active and verified
8. Store closure sizes are within documented bounds
9. System evaluation completes in <1 second
10. `.gitignore` is updated for Nix-only workflow

## Key Design Decisions

### Retained from the Original Design

The following concepts from the original Guix-based docs carry forward unchanged:
- Immutable root filesystem with read-only ext4
- ZFS for mutable data with per-role dataset tuning
- /etc overlay (lower from image, upper on ZFS)
- Generational deployment with boot counting and health checks
- SELinux enforcing mode with targeted policy
- Ignition first-boot provisioning
- Pluggable CNI architecture for Kubernetes
- systemd as init system (was already planned to replace Shepherd)
- Kernel config fragment system

### Changed from the Original Design

- GNU Guix -> Nix (stable, no flakes, no experimental features)
- Guile Scheme -> Nix language
- Docker build environment -> Native Nix builds (Docker eliminated)
- TOML config files -> Nix module options with typed defaults
- `guix system image` -> `aos system image` (Rust CLI wrapping nix-build)
- Guix channel -> single `default.nix` entry point
- Guix marionette -> custom virtio-serial guest agent (shell-based)
- Shepherd -> systemd (was already planned)
- `/gnu/store` -> `/nix/store`
- `.scm` files -> `.nix` files
- `define-public` -> Nix attrset in `pkgs/default.nix`
- `nativeBuildInputs` -> `buildDeps`, `buildInputs` -> `runtimeDeps`
- Build phases as strings -> Build phases as structured list of `{ name; script; }`
- `mkDefault`/`mkForce` -> eliminated (later modules simply override)
- Nix derivation tests + virtio-serial guest agent

## Production Checklist

- [ ] All packages build from source with no binary substitutes
- [ ] Bootstrap chain verified: hex0 -> glibc (binary reproducibility)
- [ ] All images boot to multi-user.target with systemd
- [ ] SELinux enforcing, no critical AVC denials
- [ ] Firewall active with role-appropriate rules
- [ ] SSH key-only authentication
- [ ] Health check service validates system state
- [ ] Boot counting protocol prevents bad updates from persisting
- [ ] GC cleans up old generations without affecting running system
- [ ] Fleet update tested with rolling strategy and rollback
- [ ] All documentation accurate and up-to-date

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Leftover Guix references in code or config | Medium | Confusion, broken paths | Grep for "guix", "gnu/store", ".scm" across the entire tree |
| Store closure size exceeds bounds | Low | Images too large for deployment | `aos test build` checks closure sizes; `aos why-depends` debugs bloat |
| SELinux policy has gaps in enforcing mode | Medium | AVC denials in production | Permissive mode testing first; iterative policy refinement; dontaudit for known-harmless denials |
| Performance regression in module evaluation | Low | Slow builds | Keep module count ~20; no deep fixpoint recursion; benchmark in CI |
