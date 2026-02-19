# 11. Migration Path

## Phase 1: Build Golden Image Alongside Existing Variants

- Create `systems/golden.nix` and `modules/services/cloud-init.nix`
- Create `modules/kubernetes/k3s.nix`
- Build both golden and per-variant images from the same module set
- Validate functional parity for each role

## Phase 2: Dual-Mode Support

Both Ignition and cloud-init present. Kernel parameter selects provisioner:

```
aos.provisioner=ignition   # Legacy mode
aos.provisioner=cloud-init # New default (or no parameter)
```

## Phase 3: Incremental Fleet Migration

- Convert machines one at a time from per-variant to golden image
- Same cloud-init userdata specifies the role the machine previously ran
- Validate via K8s node health and audit logs

## Phase 4: Retire Per-Variant Builds

- Remove `systems/base.nix`, `server.nix`, `seed.nix`, `k8s-worker.nix`,
  `k8s-control-plane.nix`
- Remove old Kubernetes modules (kubelet, control-plane, network,
  node-problem-detector)
- Remove monitoring modules (node-exporter, alloy)
- Remove removed service modules (nginx, nix-daemon, seed, vault-agent, sssd)
- Remove Ignition module (after all deployments migrated)
- `systems/golden.nix` is the only system definition

## Phase 5: Generation Support

- Implement generation store (store partition, profile symlinks)
- Implement per-generation UKI build and signing
- Implement `modules/base/generations.nix` (replaces `sysupdate.nix`)
- Publish system generations to APM registry
- Implement `aos system` generation management CLI
- Implement `aos gc --generations` for generation cleanup
- Test: multi-generation boot, rollback, live switch via soft-reboot

## New Packages Required

| Package | Source | Build Complexity |
|---------|--------|-----------------|
| k3s | `github.com/k3s-io/k3s` | Go build (uses existing `mkGoPackage`) |
| zfs-csi-driver | `github.com/openebs/zfs-localpv` or custom | Go build |
| cilium-cli | `github.com/cilium/cilium-cli` | Go build (for bootstrap only) |

## Packages Removed

- kubelet, kubeadm, kubectl, crictl, helm, ipvsadm, conntrack-tools
- node-exporter, alloy, smartmontools
- nginx, vault, sssd, nix (daemon)
- node-problem-detector

## `aos` CLI Updates

### System generation management (replaces old `aos system`)

```sh
aos system                          # Show current generation
aos system list                     # List all installed generations
aos system switch <gen>             # Set generation for next boot
aos system switch --now <gen>       # Live switch via soft-reboot
aos system rollback                 # Switch to previous generation
aos system rollback --now           # Live rollback via soft-reboot
aos system diff <gen-a> <gen-b>     # Package diff between generations
aos system pin <gen>                # Protect generation from GC
aos system unpin <gen>              # Allow GC of generation
```

Generation identifiers accept: full derivation hash, short hash prefix,
generation number, or relative (`-1` for previous).

### Garbage collection (extended)

```sh
aos gc                              # Default store GC (existing)
aos gc --generations                # Delete old generations + GC store
aos gc --generations --keep 3       # Keep N most recent
aos gc --generations --older-than 30d  # Delete by age
aos gc --generations --dry-run      # Show what would be removed
```

### Build and image commands

```sh
aos build golden                    # Build the golden image
aos build golden --format qcow2     # Specific format
aos build golden --all-formats      # All cloud formats
aos test vm --image golden --role k8s-worker   # Test with role
aos cloud-init validate user-data.yaml         # Validate userdata
aos cloud-init iso --output cidata.iso \       # Generate NoCloud ISO
  --instance-id bare-metal-01 \
  --hostname k8s-worker-01 \
  user-data.yaml
```
