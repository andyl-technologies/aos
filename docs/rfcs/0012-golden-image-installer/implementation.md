# RFC-0012 implementation plan — single-ESP image + repart install

This is the change plan for [RFC-0012](README.md). **Scope:** the image builder
and the first-boot substrate only — moving the EROFS root (and its dm-verity
tree) out of baked image partitions and onto the ESP as files, installed on
first boot by `systemd-repart` `CopyBlocks=` drop-ins, plus a **signed
emergency/recovery profile** on the install UKI and the PCR hardening that makes
its password-less shell sound. `apm` support for updating the install UKI /
`rootfs.bin`, writing per-generation UKIs to XBOOTLDR, and A/B activation is
**future work** and is not touched here.

> **Builds on RFC-0011 (now on `master`).** RFC-0011 already ships:
> the `systemd-repart` substrate (`modules/services/repart.nix`, carving
> swap + var), the dm-verity + signed-roothash chain (`lib/build/rootfs.nix`
> emits the tree; `pkgs/boot/aos-uki.nix` bakes `roothash=` into the signed
> cmdline via `rootHashFile`; `modules/security/verity.nix` provides the option
> surface and repoints `root=` at `/dev/mapper/root`), and the boot substrate
> units (`modules/base/boot-substrate.nix`). This plan **extends** those files;
> several rows that were "new work" in the Ignition-era draft are now
> "reconcile" or "done". Every file:line citation below refers to the
> post-RFC-0011 tree.

The end state: the image is a single 512 MiB ESP carrying sd-boot + the install
UKI (normal + emergency profiles) + `rootfs.bin` (EROFS data) + `root-a-hash.bin`
(dm-verity tree). First boot runs one `systemd-repart` pass that creates `root-a`
/ `root-a-hash` and `CopyBlocks=` the image onto them, carves swap + var, and
rewrites the GPT; `veritysetup open` assembles the mapper the signed cmdline's
root hash anchors; `sysroot.mount` mounts the verified root. Under Secure Boot a
tampered root fails closed, and the UKI's emergency profile gives
recovery-key-gated console access.

## Component overview

| # | File | Change |
|---|------|--------|
| 1 | `lib/build/rootfs.nix` | **emit the verity tree as a standalone file** (`$out/root-a-hash.bin`) alongside `root.img`, so `_builder.nix` can place it on the ESP; keep the existing `$out/root-hash` (root-hash) emission (change #9a) |
| 2 | `modules/image/_builder.nix` | **single-ESP image**: place `rootfs.bin` + `root-a-hash.bin` in the ESP, fixed `espSizeMiB` (512) with a fit assertion, **drop the `root-a` and `root-a-hash` partitions**, rewrite `image-info.json` (change #2) |
| 3 | `modules/services/repart.nix` | **add `10-root-a.conf` + `20-root-a-hash.conf` `CopyBlocks=` drop-ins**; extend `aos-repart.service` to mount the ESP as the copy source and `veritysetup open` the mapper; optional unsigned-path verify gate (changes #3, #9c) |
| 4 | `pkgs/boot/aos-uki.nix` | **build** the emergency/recovery profile — a second `.profile`/`.cmdline`, PCR-11 excluded from `.pcrsig` (change #10). (The signed `roothash=` bake already exists — `rootHashFile`, RFC-0011 F1 — no change.) |
| 5 | `modules/base/secure-boot.nix` | **add PCR 12 to the pinned `/var` seal set** (`pinnedPcrs` "7" → "7,12") so any appended-cmdline injection changes the measured value and the unseal fails closed (change #10d) |
| 6 | `modules/base/_initrd-builder.nix` | ensure `erofs-utils` in the initrd closure (for the optional `fsck.erofs` verify gate); **lock the initrd root account under Secure Boot** (`root:::` → `root:!*::` at `:519`, gated on `aos.boot.secureBoot.enable`; password hash on the unsigned image — §10c) |
| 7 | `modules/base/filesystems.nix` | make `espDevice` partlabel-based (`/dev/vda1` → `/dev/disk/by-partlabel/ESP`); `rootDevice` is **already** partlabel-based (`:100`) and verity already repoints it via `modules/security/verity.nix` (change #6) |
| 8 | `tests/fleet/install-from-image.nix` | assert the CopyBlock'd EROFS root on `root-a` + that repart created it from the ESP; this target is **unsigned** (no verity mapper), so verity/emergency-profile assertions live in `checks.fleet.secure-boot` / `measured-boot` (change #7) |
| 9 | `modules/tests/security.nix` + SB fleet suites | strengthen the `root-no-password` check to assert root's shadow field is locked (`!`/`*`); add SB-suite assertions that a normal-profile (@0) emergency drop yields no shell while the @1 profile grants one with `/var` sealed (change #7b) |
| 10 | `docs/boot/qemu-uefi.md` | rewrite the operator walkthrough for the single-ESP `dd`-and-boot flow (no Ignition config); repart owns the layout (change #8) |

---

## 1. `lib/build/rootfs.nix` — verity tree as a standalone ESP file

RFC-0011 already builds the EROFS `$out/root.img`, emits its fixed UUID
(`bdfb6fc9-0000-4000-8000-000000000001`) and the `/aos-toplevel` seed pointer,
computes the dm-verity Merkle tree, and writes the root hash (consumed by
`aos-uki` via `rootHashFile`). Today the tree is emitted such that
`_builder.nix` lays it into a baked `root-a-hash` partition
(`_builder.nix:262-291`).

**Change:** additionally emit the tree as a standalone file
`$out/root-a-hash.bin` (raw bytes, byte-reproducible via the pinned
`veritysetup format --salt=`), and keep `$out/root-hash` (the ASCII-hex root
hash) and `$out/rootfs-size-bytes` unchanged. `_builder.nix` copies
`root-a-hash.bin` onto the ESP instead of dd-ing it into a partition (change #2).
`root.img` stays exactly as it is — the EROFS data with **no** appended tree —
so `rootfs.bin` = `root.img` is a clean EROFS blob and the tree is a separate
file; this two-file split maps 1:1 onto the two `CopyBlocks=` drop-ins (§3) and
onto RFC-0011's existing two-partition (`root-a` + `root-a-hash`) verity shape,
rather than the single appended-tree blob the Ignition-era draft proposed.

`rootfs-size-bytes` (the EROFS data size) and the tree size are surfaced in
`image-info.json` (change #2) as the minimum sizes repart's `root-a` /
`root-a-hash` drop-ins declare.

---

## 2. `modules/image/_builder.nix` — single-ESP image

This is the load-bearing change. Today the builder writes an ESP **and** a
`root-a` partition (the EROFS) **and**, under verity, a `root-a-hash` partition
(`_builder.nix:286-291`). After this change it writes **only the ESP**, with
`rootfs.bin` and `root-a-hash.bin` as files inside it.

### 2a. ESP size constant + fit assertion

Replace the "size to contents ×2" logic (`_builder.nix:242-249`) with a fixed
`espSizeMiB` (default 512) and assert the contents fit:

```nix
# Fixed ESP size (MiB). The ESP must hold sd-boot, the install UKI, the EROFS
# rootfs.bin, and the verity tree root-a-hash.bin; 512 MiB fits the current
# server closure (~160 MiB rootfs.bin, plus a few-MiB tree and the UKI) with
# comfortable headroom. Raise this if the build-time fit assertion (below) trips.
espSizeMiB ? 512,
```

In the build script, drop the `esp_mib=$(( … *2 … ))` computation and instead:

```sh
# ── Create vfat ESP image (fixed size, contents asserted to fit) ──
esp_content_kib=$(du -sk esp | cut -f1)
esp_mib=${toString espSizeMiB}
# Reserve ~32 MiB for FAT structures + slack; fail loudly if rootfs.bin +
# root-a-hash.bin + UKI outgrow the ESP rather than overflowing at mcopy time.
if [ $(( esp_content_kib + 32768 )) -gt $(( esp_mib * 1024 )) ]; then
  echo "ERROR: ESP contents ($(( esp_content_kib / 1024 )) MiB) + overhead" \
       "exceed espSizeMiB ($esp_mib MiB). Raise aos image espSizeMiB." >&2
  exit 1
fi
esp_bytes=$(( esp_mib * 1048576 ))
esp_sectors=$(( esp_bytes / 512 ))
```

### 2b. Put `rootfs.bin` + `root-a-hash.bin` in the ESP, not in partitions

In the "Populating ESP tree" step, after copying the UKI, add the root image and
its tree:

```sh
# The EROFS root and its verity tree ship as files on the ESP. aos-repart's
# CopyBlocks= drop-ins copy them onto the root-a / root-a-hash partitions it
# creates on first boot (systemd-repart has no EROFS mkfs and must copy a raw
# image). rootfs.bin is the largest object on the ESP — it drives the
# espSizeMiB budget.
cp "$ROOT_IMG" esp/rootfs.bin
${lib.optionalString verityEnabled ''cp "${rootfs}/root-a-hash.bin" esp/root-a-hash.bin''}
```

`$ROOT_IMG` is already wired (`ROOT_IMG = "${rootfs}/root.img";`,
`_builder.nix:162`). The existing `mcopy -s` loop over `esp/*` picks both files
up unchanged. Remove the now-unused `cp "$ROOT_IMG" root.img`
(`_builder.nix:190`), the `root_sectors`/`hash_sectors` computation
(`:261-273`), and the second/third `dd`s into partitions (`:289-301`).

### 2c. Single-partition GPT table

Replace the multi-line `sfdisk` table (`_builder.nix:286-291`) with an ESP-only
table:

```sh
# ── Assemble final GPT image (ESP only) ─────────────────────────────
# 1 MiB at the front for GPT header + alignment, 1 MiB at the end for the
# backup header. Everything after the ESP is unallocated free space that
# systemd-repart partitions on first boot from the AOS-baked repart.d drop-ins
# (root-a, root-a-hash, swap, var). aos-repart rewrites the GPT backup header
# to the true device end when the image lands on a larger disk.
disk_sectors=$(( ${toString espStartSector} + esp_sectors + 2048 ))
disk_bytes=$(( disk_sectors * 512 ))
truncate -s "$disk_bytes" image.raw

sfdisk image.raw <<PTABLE
label: gpt
size=$esp_sectors, type=${espGuid}, name="ESP"
PTABLE

dd if=esp.img of=image.raw bs=512 seek=${toString espStartSector} \
   conv=notrunc status=none
```

`linuxGuid` and `verityGuid` are no longer used by the builder to place
partitions (repart's drop-ins carry the type GUIDs now); keep `verityGuid` only
if `image-info.json` still records the expected `root-a-hash` type for tooling,
else drop both.

### 2d. `image-info.json`

Rewrite the metadata to describe the single-partition artifact, surface the
`rootfs.bin` / tree sizes as the `root-a` / `root-a-hash` minimums, and document
the first-boot contract for downstream tooling:

```nix
cat > $out/image-info.json <<META
{
  "name": "${name}",
  "version": "${version}",
  "diskSizeMiB": $disk_size_mib,
  "espSizeMiB": $esp_size_mib,
  "rootfsBinBytes": $root_size_bytes,
  "rootfsBinUuid": "bdfb6fc9-0000-4000-8000-000000000001",
  "rootHashBinBytes": $hash_size_bytes,
  "format": "raw",
  "partitionTable": "gpt",
  "partitions": [
    { "number": 1, "label": "ESP", "type": "esp", "filesystem": "vfat", "sizeMiB": $esp_size_mib }
  ],
  "esp": {
    "uki": "EFI/Linux/${ukiFilename}",
    "sdBoot": "EFI/systemd/systemd-bootx64.efi",
    "rootfsBin": "rootfs.bin",
    "rootHashBin": "root-a-hash.bin"
  },
  "firstBoot": {
    "provisioner": "systemd-repart (modules/services/repart.nix) CopyBlocks= drop-ins",
    "installs": "esp/rootfs.bin -> root-a, esp/root-a-hash.bin -> root-a-hash",
    "createdPartlabels": ["root-a", "root-a-hash", "swap", "var"],
    "rootAMinBytes": $root_size_bytes
  }
}
META
```

> The `imageDrv // {inherit uki;}` passthru (used by RFC-0006 phase 4
> `apr publish --image`) is unchanged.

---

## 3. `modules/services/repart.nix` — root-install drop-ins + ESP copy source

RFC-0011's `aos-repart.service` already runs one `systemd-repart` pass over a
baked `repart.d` directory (`50-swap.conf` + `60-var.conf`), rewrites the GPT to
the device end, and settles udev. This change adds the root-install drop-ins
ahead of them and teaches the service to mount the ESP as the `CopyBlocks=`
source.

### 3a. New `CopyBlocks=` drop-ins

Add two definitions, ordered before swap/var by filename:

```nix
# root-a: the EROFS root, copied verbatim from the ESP. CopyBlocks= is
# systemd-repart's raw block copy — the dd of the Ignition-era draft, now a
# convention drop-in. SizeMinBytes is the image's rootfs-size-bytes; repart
# creates the partition at least that large. Linux-data type GUID matches the
# root=/dev/disk/by-partlabel/root-a the signed cmdline pins.
rootAConf = ''
  [Partition]
  Type=linux-generic
  Label=root-a
  CopyBlocks=/run/aos-esp/rootfs.bin
  SizeMinBytes=${rootfs-size}
  SizeMaxBytes=${rootfs-size}
'';

# root-a-hash: the dm-verity Merkle tree, copied verbatim. The root-verity DPS
# type GUID (2C7357ED-…) is DISTINCT from root-a's Linux-data GUID — required so
# repart CREATES this partition instead of matching it to root-a (same reasoning
# as the deferred root-b in the swap/var note below).
rootAHashConf = ''
  [Partition]
  Type=root-verity
  Label=root-a-hash
  CopyBlocks=/run/aos-esp/root-a-hash.bin
  SizeMinBytes=${hash-size}
  SizeMaxBytes=${hash-size}
'';
```

Written to `50-root-a.conf`-style names ordered **before** swap/var:
`10-root-a.conf`, `20-root-a-hash.conf`, then the existing `50-swap.conf` /
`60-var.conf`. repart applies them in filename order, placing `root-a` and its
tree immediately after the ESP, then swap, then growing `var` into the tail.

These drop-ins are gated on the image actually shipping the files — i.e.
contributed only when `rootfs.bin` is baked onto the ESP (a builder-set option,
e.g. `aos.provisioning.repart.installRoot`, or simply keyed on
`config.aos.image.singleEsp`). On the kernel-boot VM test (no ESP, no
`rootfs.bin`) the drop-ins are absent and repart carves only swap/var exactly as
today.

### 3b. Mount the ESP + open verity in `aos-repart.service`

Extend the existing `aos-repart.service` script (`repart.nix:169-209`):

```sh
# Mount the ESP read-only so the CopyBlocks= sources (/run/aos-esp/{rootfs.bin,
# root-a-hash.bin}) resolve. The path is fixed because CopyBlocks= is a static
# path in the drop-in. On a kernel-boot test there is no ESP partlabel, the
# root-install drop-ins are absent, and this block is skipped.
if [ -e /dev/disk/by-partlabel/ESP ] && [ -e /run/aos-esp-needed ]; then
  mkdir -p /run/aos-esp
  mount -t vfat -o ro,nodev,nosuid /dev/disk/by-partlabel/ESP /run/aos-esp
fi

systemd-repart --definitions=${repartDefinitions}/repart.d \
  --dry-run=no --empty=allow "/dev/$disk" > /dev/kmsg 2>&1

# Assemble the verity mapper from the SIGNED root hash (§9c) once root-a /
# root-a-hash exist, before sysroot.mount consumes /dev/mapper/root.
```

Add `pkgs.cryptsetup` (for `veritysetup`) and, for the optional verify gate,
`pkgs.erofs-utils` to the `repartTools` PATH list (`repart.nix:151-162`).

**Optional unsigned-path verify gate.** Pure repart will not re-`CopyBlocks` an
existing `root-a` (it matches the partition entry), so a crash mid-copy on the
**unsigned** dev image — which has no verity backstop — could leave a
mountable-but-corrupt root. Guard that path only: after repart, if `root-a`
exists but `fsck.erofs /dev/disk/by-partlabel/root-a` fails **and** no verity is
active, wipe the partition entry and re-run repart once. Under Secure Boot this
gate is unnecessary (verity fails closed) and is skipped. This restores the one
safety property the Ignition-era `fsck.erofs` re-`dd` had that plain repart
lacks.

### 3c. `aos-gpt-relocate` is already gone

The Ignition-era draft reworked `aos-gpt-relocate` to key off the ESP. RFC-0011
**deleted** it — `systemd-repart` rewrites the GPT and the backup header to the
device end natively (`repart.nix` header comment). No action.

---

## 4. `pkgs/boot/aos-uki.nix` — emergency/recovery profile

The signed `roothash=` bake already exists (`aos-uki.nix` `rootHashFile`, the
RFC-0011 F1 trick at `aos-uki.nix:113-124`) — **no change** to the verity
anchor. This change adds the second **profile**.

### 4a. Build the profile

Assemble a multi-profile UKI with `ukify` (v259.1): profile 0 = the normal
cmdline (+ `roothash=` from `rootHashFile`); profile 1 = the same plus
`rd.systemd.unit=aos-recovery.target` (the autologin recovery target of §10c —
**not** `emergency.target`, which would hit `sulogin` and refuse under the locked
root). sd-boot renders one menu entry per profile
(`src/boot/boot.c:2177-2263`) and the `@N` selector survives the SB cmdline-drop
(`stub.c:188`, `:1232-1245`); `editor no` stays on. The v259.1 mechanism is a
two-step build:
`ukify build --profile='ID=emergency\n…' --cmdline='… rd.systemd.unit=aos-recovery.target' --output=profile-emergency.efi`,
then the main `ukify build … --profile='ID=main\n…' --join-profile=profile-emergency.efi …`.
`--profile`/`--join-profile` landed in v257 and `--sign-profile` in v258
(`man/ukify.xml`); the join is at `ukify.py:1483-1512`.

### 4b. Exclude the emergency profile from the signed PCR policy

The `/var` seal is signature-flexible on PCR 11
(`secure-boot.nix:438-439`). The emergency profile's PCR-11 prediction **must
not** be blessed by the signed `.pcrsig`, or the TPM auto-unseals `/var` for
whoever selects it. v259.1 `ukify` does exactly this via `--sign-profile=main`:
it signs the PCR-11 policy only for profiles whose `.profile` `ID=` matches
(`ukify.py:1515-1520`), so the emergency profile (`ID=emergency`) gets **no**
signed prediction. At boot the stub overrides `sections[]` with the selected
profile's `.cmdline`/`.profile` (`stub.c:1148-1158`) and measures them into
PCR 11, so selecting the emergency profile yields a PCR-11 value with no matching
signature in `.pcrsig` → the runtime TPM2 unseal (bound by
`--tpm2-public-key-pcrs=${signedPcrs}` at `secure-boot.nix:438`) fails closed and
the recovery key is required. **Build constraint (both directions):** the
emergency profile's `ID=` MUST be **distinct** from any `--sign-profile=` value,
or the exclusion does not happen; and the **main** profile's `ID=` MUST **match**
a `--sign-profile=` value, or profile 0 is *also* left unsigned and a normal @0
boot cannot auto-unseal `/var` either. A CI assertion (change #7b) proves the
emergency profile reaches the shell and leaves `/var` sealed.

---

## 5. `modules/base/secure-boot.nix` — bind PCR 12 into the `/var` seal

The seal today is signature-flexible on PCR 11 + pinned by value on PCR 7
(`secure-boot.nix:438-439`: `--tpm2-public-key-pcrs=${signedPcrs}`,
`--tpm2-pcrs=${pinnedPcrs}`). Add **PCR 12** to the pinned set
(`pinnedPcrs` option default "7" → "7,12", `:218`). PCR 12
(`TPM2_PCR_KERNEL_CONFIG`) measures the *override/appended* kernel cmdline (not
the embedded base, which is PCR 11), loaded credentials, confext, and the
selected-profile event — i.e. **everything an attacker can append** (the SMBIOS
cmdline lands here at `stub.c:814`, addons at `:389`). Pinning it means any
injected `roothash=`, `SYSTEMD_SULOGIN_FORCE=1`, or `rd.systemd.unit=` changes
the measured value, so the TPM refuses to release `/var` — closing the
injection→`/var` path that locked-root alone does not.

Caveats, both load-bearing:

- **PCR 12 can only be *pinned by value*, not signed.** `systemd-measure` models
  PCR 11 only, so there is no signed PCR-12 prediction; the pin is captured at
  first-boot enrollment, as brittle as PCR 7. Sound **today** because AOS extends
  *nothing* into PCR 12 on a clean @0 boot (no addons, no SMBIOS extra, no
  credentials, no confext — verify by grep), so the value is the constant reset
  state. It becomes a regression the moment any AOS feature legitimately touches
  PCR 12 — document as a standing constraint, and re-seal if it changes. Note
  **sysext** images measure into PCR **13** (`TPM2_PCR_SYSEXTS`), *not* 12, so
  adopting sysexts would need a separate PCR-13 pin — the PCR-12 pin here does
  **not** cover them.
- **PCR-12 pinning does not fix verity.** It stops an injected boot from
  *unsealing `/var`*, but the injected `roothash=` still anchors the verity
  device unless §9c's duplicate-rejection guard is in place — so §9c and this
  change are both required.

Bonus: the @1 emergency profile extends PCR 12 with its profile event
(`stub.c:1203-1217`), so @1's PCR 12 differs from @0's — pinning to @0's value
also denies @1, reinforcing the PCR-11 exclusion.

---

## 6. `modules/base/_initrd-builder.nix` — lock initrd root; erofs-utils

RFC-0011's initrd already carries `cryptsetup` (for `veritysetup` + the `/var`
recovery slot), `dd`, `blkid`, `mount`, `umount` (`coreutils` + `util-linux`).
Two changes:

- **`erofs-utils`** in the initrd closure so `fsck.erofs` is available for the
  optional unsigned-path verify gate (§3b). RFC-0011's rendered units embed
  `environment.PATH = bootPath`; adding `erofs-utils` to the repart tools list
  (§3b) pulls it into the initrd via the unit references, the same path by which
  `jq`/`e2fsprogs` reach the initrd. Add `pkgs.erofs-utils` to `initrdPackages`
  (`:71`) for explicitness.
- **Lock the initrd root account under Secure Boot.** The initrd `root` shadow
  line is currently **empty** (`_initrd-builder.nix:519` =
  `root:::0:99999:7:::`), so any emergency drop yields a passwordless `sulogin`.
  Make it **conditional on `aos.boot.secureBoot.enable`**: **locked**
  (`root:!*::0:99999:7:::`) on the signed image — so `sulogin` (run by
  `emergency.service`/`rescue.service`) **refuses** and the @0 fallback fails
  closed — and a **password hash** on the unsigned dev image (the non-SB
  `sulogin`-protected posture), since one static shadow line cannot be both. The
  heredoc is emitted at `:518-519`.

---

## 7. `modules/base/filesystems.nix` — partlabel ESP device

RFC-0011 already made `rootDevice` partlabel-based
(`filesystems.nix:100` = `/dev/disk/by-partlabel/root-a`), and
`modules/security/verity.nix` repoints it to `/dev/mapper/root` when verity is
active — so the Ignition-era draft's change #6/#9d for the *root* device is
**done**. The one remaining default is `espDevice`, still `/dev/vda1`
(`filesystems.nix:114`); make it partlabel-based so the ESP mount is
partition-number independent:

```nix
espDevice = lib.mkOption {
  type = lib.types.str;
  default = "/dev/disk/by-partlabel/ESP";
  description = "Block device for the EFI System Partition.";
};
```

No `systems/*.nix` profile overrides it (checked). The fstab `/boot` mount stays
on the ESP (`espDevice → /boot vfat ro`, `filesystems.nix:51`); the
XBOOTLDR-at-`/boot` + ESP-at-`/efi` split lands with the `apm` follow-up. `var`
and swap entries are unchanged (they already key off partlabels).

---

## 8. `tests/fleet/install-from-image.nix` — exercise the CopyBlocks install

`checks.fleet.install-from-image` is the canonical runtime test. RFC-0011
already migrated it to the new path (`provisioning = "newpath"`,
`varProvisioning`; no `instanceMetadata`). For this RFC, extend it to the
single-ESP image (`espSizeMiB`, root shipped on the ESP) and assert the
repart-installed root.

### Assertion changes

RFC-0011's test already asserts `root-a`/`swap`/`var` exist, the root is
read-only EROFS smaller than its partition, `/var` filled the disk, and gen-1
seeded. Adjust and add:

```python
# The repart-created layout exists (now root-a is CopyBlock'd, not baked).
for label in ("root-a", "root-a-hash", "swap", "var"):
    target.succeed(f"test -e /dev/disk/by-partlabel/{label}")

# aos-repart CopyBlock'd the shipped EROFS: root-a's UUID matches the image's.
root_uuid = target.succeed(
    "blkid -s UUID -o value /dev/disk/by-partlabel/root-a"
).strip()
assert root_uuid == "bdfb6fc9-0000-4000-8000-000000000001", root_uuid

# The provisioning pass ran and completed.
target.succeed("systemctl is-active aos-repart.service")
```

The `stat -f` EROFS-size and `/var` assertions key off mount points, not
partition numbers, so they are unaffected. The reboot leg proves idempotency:
on the post-reboot boot repart must make no change (all partitions exist) and the
system must come back on the upgraded generation with no failed units. This
target is **unsigned** (no verity mapper), so the verity-mapped-root and
emergency-profile assertions live in the SB suites (§9 below).

---

## 9. `modules/tests/security.nix` + SB fleet suites — verity + emergency

The verity-mapped root and the emergency profile are Secure-Boot properties, so
they belong in `checks.fleet.secure-boot` / `measured-boot`, which already boot
the signed, verity-enabled image (RFC-0006 + RFC-0011). Add:

- **Verity-mapped root mounts; corrupt `root-a` fails closed.** Assert `/` is
  backed by `/dev/mapper/root`; a fault-injected bad block on `root-a` yields
  `EIO` and the boot drops to emergency (verity catches it).
- **@1 emergency profile reaches the recovery shell and does *not* unseal
  `/var`.** Select the @1 profile; assert the initrd recovery shell is reached
  and `/var` stays sealed (the recovery key is required).
- **@0 drop into `emergency.target` yields no shell.** With the locked root
  (§6), `sulogin` refuses — the @0 fallback fails closed.
- **Strengthen `modules/tests/security.nix` `root-no-password`.** Today a no-op
  (`test -f /etc/shadow` only); assert root's shadow field is locked (`!`/`*`) on
  the SB posture.

---

## 10. `docs/boot/qemu-uefi.md` — operator walkthrough

Rewrite the by-hand walkthrough for the single-ESP flow: `dd` the ≈514 MiB image
onto an oversized disk and boot — `systemd-repart` creates `root-a`,
`root-a-hash`, swap, and `var` and CopyBlocks the root on first boot, with **no
operator storage config** (RFC-0011 removed Ignition; the substrate is
AOS-baked). Drop the old Ignition config block entirely. Keep the doc one-for-one
with `checks.fleet.install-from-image` (RFC-0003's "doc and test cannot drift"
principle).

---

## Work-item checklist (suggested order)

1. **`rootfs.nix`** — emit `root-a-hash.bin` as a standalone file (change #1).
2. **`_builder.nix`** — single-ESP image + `rootfs.bin`/`root-a-hash.bin` on the
   ESP, `espSizeMiB` + fit assertion, `image-info.json` (change #2). Build
   `nix-build -A <system>.config.system.build.image`; inspect with `sfdisk -d` /
   `mdir`.
3. **`repart.nix`** — root-a / root-a-hash `CopyBlocks=` drop-ins + ESP mount +
   `veritysetup open` + optional verify gate (changes #3, #9c).
4. **`aos-uki.nix`** — emergency profile (change #4/#10).
5. **`_initrd-builder.nix`** — `erofs-utils` + lock initrd root under SB
   (`:519`, change #6).
6. **`secure-boot.nix`** — add PCR 12 to `pinnedPcrs` (change #5/#10d).
7. **`filesystems.nix`** — partlabel `espDevice` (change #7).
8. **`install-from-image.nix`** — single-ESP config + CopyBlocks assertions
   (change #8).
9. **`security.nix` + SB suites** — verity/emergency assertions (change #9).
10. **`qemu-uefi.md`** — operator walkthrough (change #10).

## Testing / validation

- `nix-build -A checks.eval` — module eval (option defaults, the new drop-ins,
  the boot.nix assertion still passes).
- `nix-build -A checks.vm.boot` — a kernel-boot VM test must still pass: the
  ext4-root path has no `ESP` partlabel and no `rootfs.bin`, so the root-install
  drop-ins are absent and `aos-repart` carves only swap/var (exactly RFC-0011's
  behavior). Confirm no `dev-…-ESP.device` dependency is introduced (it would
  queue ~90 s on the missing device; `lib/testing/vm.nix:53-57` documents this
  for `cryptswap`, and `repart.nix` already keys off `root-a`, not `ESP`).
- **`checks.fleet.install-from-image`** — the real end-to-end proof: UEFI →
  sd-boot → install UKI → `systemd-repart` creates + CopyBlocks `root-a` → boot
  on EROFS `root-a` → `apm upgrade --system` → reboot → idempotent (repart makes
  no change), system healthy. This is the gate for the change.
- **`checks.fleet.secure-boot` / `measured-boot`** — verity-mapped root + the @0/@1
  emergency-profile assertions (§9).
- Inspect the built image (`mdir -i esp.img ::`) to confirm `rootfs.bin` +
  `root-a-hash.bin` are present and the partition table has exactly one
  partition.

## Risks & migration

- **Breaking image-format change.** The shipped image no longer carries `root-a`
  / `root-a-hash`; there is no in-place migration from the RFC-0011 caveat-#3
  image — re-deploy from the new artifact. AOS is pre-release, so no fielded
  installs depend on the old layout.
- **ESP budget caps root growth.** `rootfs.bin` + tree must stay within
  `espSizeMiB` minus the UKI and FAT overhead. The build-time assertion turns an
  overflow into a clear build failure (raise `espSizeMiB`).
- **`CopyBlocks` power-fail-safety.** Pure repart will not re-copy an existing
  partition entry; a crash mid-copy is caught by verity (fail-closed) under
  Secure Boot and by the optional `fsck.erofs` gate (§3b) on the unsigned dev
  image. Documented, not hidden.
- **`vfat` availability.** `CONFIG_VFAT_FS=y` is builtin
  (`pkgs/kernel/config/storage.config`) and the ESP vfat mount is already proven
  by the current `/boot` mount + green `install-from-image`. The ESP mount that
  `aos-repart` adds for the copy source (§3b) uses the same builtin.
- **Verity reproducibility.** `veritysetup format` must use a pinned `--salt=`
  (RFC-0011 already does) so the tree and root hash are byte-reproducible; the
  root hash is a build output, so `aos-uki` reads it from the rootfs derivation
  (no import-from-derivation) — unchanged.
- **`ukify` multi-profile + PCR policy.** Confirmed against the systemd v259.1
  clone: multi-profile UKIs build via `--profile`/`--join-profile` (v257) and the
  signed PCR policy is scoped per profile via `--sign-profile` (v258), so the
  emergency profile's PCR-11 prediction is excluded from `.pcrsig` and it cannot
  auto-unseal `/var`. The one build constraint is the distinct `.profile` `ID=`;
  CI (change #9) asserts the property end-to-end.
