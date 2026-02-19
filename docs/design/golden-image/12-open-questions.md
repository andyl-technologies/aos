# 12. Open Questions

1. **Cloud-init vs Ignition scope**: This proposal retains Ignition for
   storage provisioning (ZFS pool creation in initrd) and uses cloud-init
   for service configuration (real root). Should cloud-init subsume Ignition
   entirely? Ignition's atomic "fail = don't boot" semantics are stronger
   than cloud-init's "best-effort, retry next boot" model.

2. **Upstream cloud-init vs AOS-native**: Upstream cloud-init has a large
   Python dependency chain. The proposal can use either:
   - Shell-based scripts reading userdata + copying pre-rendered templates
   - Full upstream cloud-init built as an AOS package from source
   - Hybrid: shell scripts for AOS-specific modules, upstream for
     datasource detection

3. **ZFS CSI driver selection**: Options include:
   - OpenEBS ZFS LocalPV (mature, CNCF sandbox)
   - Custom minimal CSI driver built from source
   - k3s local-path-provisioner with ZFS backend
   Trade-off is maturity vs build complexity vs feature set.

4. **Userdata security on bare-metal**: Cloud provider IMDS provides
   instance isolation. On bare-metal, the config drive should be encrypted
   or served over mTLS from a provisioning server. The Ed25519 signature
   envelope addresses this for network-delivered configs.

5. **Cilium installation method**: Options:
   - k3s HelmChart CRD (auto-deploys on first CP boot)
   - Pre-baked Cilium container images in the golden image
   - cilium-cli bootstrap from cloud-init final stage
   The HelmChart CRD approach is simplest but requires internet access
   on first boot. Pre-baking images makes the image larger but enables
   air-gapped installs.

6. **k3s build from source**: k3s has a complex build process that vendors
   Kubernetes components. Needs investigation of whether `mkGoPackage` can
   handle the k3s build or if a custom build phase is needed.

7. **Store partition integrity**: Store paths are content-addressed (hash
   in path name), so tampering is detectable on read. For stronger
   guarantees, options include:
   - Nix overlay store: dm-verity protected base layer (shipped image) +
     writable upper layer (APM additions). Base is verified; upper is
     content-addressed.
   - Full dm-verity on the store partition (requires re-hashing on every
     generation install — expensive).
   - Accept content-addressing as sufficient (store paths are verified by
     APM on download via NAR hash; runtime reads trust the store).

8. **Live switch and running containers**: When `systemd soft-reboot` kills
   all userspace, what happens to running Kubernetes pods? The kernel stays
   running, so cgroups and namespaces persist briefly, but containerd
   restarts. k3s and containerd should reconnect to existing containers
   after restart. Needs testing to verify pod continuity vs. restart.

9. **ESP sizing for N generations**: Each generation's UKI is ~15 MB.
   With 5 retained generations, that's ~75 MB. The 1 GB ESP is sufficient,
   but the configurable retention limit must account for ESP capacity.
   Should the ESP size be increased for operators who want many generations?

10. **TPM PCR 11 and multi-generation**: Each generation has a different
    UKI hash, changing PCR 11. If LUKS unsealing binds to PCR 11, switching
    generations breaks unsealing. Options:
    - Don't bind to PCR 11 (weaker but practical)
    - Use `systemd-pcrlock` to pre-authorize expected PCR values for
      known generations
    - Re-seal LUKS to new PCR values on each generation install

11. **Generation diffing**: `aos system diff` should show package-level
    diffs (added/removed/upgraded packages) between generations. This
    requires storing a package manifest per generation or computing diffs
    from store path closures.

12. **Generation metadata in APM registry**: Is a system generation
    published to the registry as a single TOML entry with its full closure,
    identical to any other package? Or does it need a dedicated system
    generation schema with additional metadata (version contract,
    compatible userdata versions, kernel version, etc.)?
