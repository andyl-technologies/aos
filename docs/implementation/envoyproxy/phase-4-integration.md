# Phase 4: Integration and Testing

**Dependency:** Phase 3 (Envoy binary)

## Objective

Integrate the Envoy binary into the golden image, create the
`buildBazelPackage` helper for future Bazel-based packages, and validate
with integration tests.

## Prerequisites

- Phase 3 complete: working `envoy` binary
- Golden image system variant (`systems/golden.nix`) exists
- VM test infrastructure (`lib/testing/vm.nix`) working

## Deliverables

- `lib/bazel.nix` -- `buildBazelPackage` helper (optional, for future use)
- Updated `systems/golden.nix` with Envoy package
- Integration tests for Envoy within the golden image

## Detailed Task Checklist

### 4.1 buildBazelPackage Helper (Optional)

If Envoy is the only Bazel-based package, this can be deferred. If more
Bazel packages are anticipated (e.g., TensorFlow, gRPC standalone), build
the helper now.

- [ ] Write `lib/bazel.nix`:
  - [ ] Accept `fetchAttrs` (FOD config) and `buildAttrs` (build config)
  - [ ] Abstract the two-phase pattern:
    - Phase 1: FOD with `outputHashMode = "recursive"`
    - Phase 2: Unpack deps, set `--repository_disable_download`, build
  - [ ] Convert `NIX_CFLAGS_COMPILE` / `NIX_LDFLAGS` to `--copt` / `--linkopt`
  - [ ] Remove built-in workspaces (rules_cc, local_config_cc, embedded_jdk)
  - [ ] Clean VCS directories (.git, .svn, .hg)

### 4.2 Golden Image Integration

- [ ] Add `envoy` to the golden image package list in `systems/golden.nix`
- [ ] Configure Envoy as a systemd service (optional, Cilium manages it):
  - [ ] Only needed if running Envoy standalone (not via Cilium)
  - [ ] Cilium embeds its own Envoy config; standalone is for edge proxy use
- [ ] Update image size estimate (envoy adds ~100 MB to the static binary)

### 4.3 Cilium + Envoy Integration

- [ ] Verify Cilium's `envoy: enabled: true` HelmChart configuration
  points to the AOS-built Envoy binary
- [ ] Test L7 network policy enforcement with Envoy:
  - [ ] HTTP path-based policy
  - [ ] Rate limiting
  - [ ] mTLS between pods

### 4.4 Testing

- [ ] Basic smoke test:
  - [ ] `envoy --version` succeeds
  - [ ] `envoy --mode validate -c <minimal-config>` validates config
- [ ] VM boot test with Envoy:
  - [ ] Golden image boots with Envoy in PATH
  - [ ] Envoy starts with a basic listener/cluster config
  - [ ] Envoy proxies HTTP traffic between two endpoints
- [ ] Build reproducibility:
  - [ ] Build envoy twice, compare output hashes
  - [ ] FOD hashes are stable across builds

### 4.5 Documentation

- [ ] Update golden image docs to reference AOS-built Envoy
- [ ] Document Envoy version upgrade procedure:
  - [ ] Update source hash in `envoy.nix`
  - [ ] Rebuild envoy-deps FOD (hash changes with each version)
  - [ ] Check if patches still apply; update if needed
  - [ ] Rebuild envoy from source
- [ ] Document Bazel version upgrade procedure (similar pattern)

## Maintenance Considerations

Envoy and Bazel are fast-moving projects. Expect maintenance work:

- **Envoy updates:** New versions may change Bazel deps, break patches.
  Budget 2-4 hours per minor version bump.
- **Bazel updates:** Major version bumps (7 -> 8) require new patches,
  new FOD hashes, and potentially new bootstrap binaries.
- **Patch drift:** The system Python, system C/C++, and rules_rust patches
  are version-specific. Track nixpkgs for updated patches.
- **FOD hash updates:** Any change to Bazel or Envoy version changes the
  FOD hash. Build with dummy hash to discover new hash.
