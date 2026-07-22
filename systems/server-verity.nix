##! systems/server-verity.nix — measured-boot + dm-verity root + repart substrate
##!
##! The production integrity-anchoring variant. Builds on
##! systems/server-measured-boot.nix (erofs root via the server profile, Secure
##! Boot signing + enrollment, signed-PCR-policy measured boot, TPM2-sealed
##! /var) and additionally turns on:
##!
##!   * dm-verity root anchoring (F1) — the read-only erofs root carrying the
##!     base lib + on-host evaluator is Merkle-hashed at build time, the hash
##!     tree ships in a `root-a-hash` GPT partition, and the root hash is baked
##!     into the measured UKI `.cmdline` (`roothash=<hex>`) so PCR 11
##!     transitively covers every byte of the root. Tampering fails dm-verity at
##!     read time (boot fails closed) or moves PCR 11 (sealed /var won't unlock)
##!     and breaks the db Authenticode signature.
##!
##!   * the systemd-repart convention substrate — carves + grows /var (and swap)
##!     in the initrd from image-baked repart.d drop-ins; under measured boot
##!     /var is left raw for aos-var-crypt to LUKS2-seal.
##!
##! Auto-registers as `systems.server-verity`.
{...}: {
  imports = [./server-measured-boot.nix];

  # F1: anchor the immutable erofs root to measured boot via dm-verity. The
  # server profile already sets rootFsType = "erofs" (required by the verity
  # assertion). This flips on the build-side hash tree (lib/build/rootfs.nix),
  # the root-a-hash partition (modules/image/_builder.nix), the roothash-on-
  # cmdline append (pkgs/boot/aos-uki.nix), and the eval-side
  # systemd-veritysetup-generator params + /dev/mapper/root retarget
  # (modules/security/verity.nix).
  aos.security.verity.enable = true;

  # systemd-native substrate provisioning is structural for every system.
}
