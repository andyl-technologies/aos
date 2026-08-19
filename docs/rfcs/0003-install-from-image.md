# RFC-0003: Installation from image — UEFI + Ignition first boot, CI-enforced

- **Status:** Implemented — `checks.fleet.install-from-image` runs the
  full five-step flow (UEFI image boot → ignition disks-stage install →
  `apm update`/`install`/`upgrade --system` → reboot into the new
  generation) green in CI.
- **Date:** 2026-06-12
- **PR:** [#100](https://github.com/andyl-technologies/aos/pull/100)
- **Audience:** anyone working on `pkgs/boot/`, `lib/testing/`,
  `modules/services/ignition.nix`, `tests/fleet/`, or the operator docs
  under `docs/boot/`.

## Problem

A new user's journey onto AOS is five steps:

1. install AOS from scratch onto a machine,
2. boot the installed system,
3. update package metadata from the registry,
4. install packages,
5. upgrade the system to a new generation.

Steps 2–5 are covered by porcelain-driven tests today
(`checks.vm.system-boot`, the `checks.vm.apm.*` suites, and the
two-node `checks.fleet.apm-e2e` / `apm-registry-upgrade` /
`apm-system-upgrade` scenarios). Step 1 is not covered anywhere — and
deliberately has no installer porcelain to cover, because AOS follows
the CoreOS model: **installation is booting a stock image and letting
Ignition's first-boot stages provision the machine.** There is no
cloud-init; cloud user-data endpoints are just delivery channels that
`ignition-fetch` reads natively per platform
(`pkgs/boot/aos-platform-detect.nix`).

The machinery for this is fully built. `modules/services/ignition.nix`
wires the complete stage pipeline (fetch → disks → mount → files →
umount) into the systemd initrd, with `sgdisk`/`wipefs`/`mkfs.ext4`
available to the stages, a GPT backup-header fixup before
`ignition-disks` (for images dd'd onto larger volumes), and
`aos-growfs` growing `root-a` afterward. `docs/boot/qemu-uefi.md`
documents the whole flow by hand: build `server-image-raw`
(self-bootable, sd-boot + UKI), oversize the disk, boot under OVMF, and
deliver an Ignition config over `-fw_cfg` that grows `root-a`, creates
`root-b`/`swap`/`var` (the A/B layout), formats filesystems, and drops
an SSH key.

But nothing executes that flow in CI:

- **No runtime test of the disks stage.** The only runtime Ignition
  test (`modules/tests/ignition.nix`) covers the files stage. The test
  harness's Ignition format is built with `allowStorageHardware =
  false` (`lib/testing/metadata.nix`), and `checks.ignition-format`
  pins that rejection — so no VM test can even *express* a
  partitioning config today.
- **No UEFI boot in CI.** Every harness boots via direct kernel boot
  (`-kernel`/`-initrd` in `lib/testing/vm.nix` and
  `pkgs/tools/aos/aos-test-driver/aos_test_driver/qemu.py`). The
  sd-boot → UKI path that real users boot through is never exercised.
- **No test of the qemu/fw_cfg platform path.** All tests deliver
  Ignition via the metadata ISO, which forces `PLATFORM_ID=file`.
- **`aos-growfs` and `ignition-disks` run on every VM boot but nothing
  asserts their effect** (the test image sizes `root-a` exactly, so
  growfs is a no-op).

The consequence: the installation guide is prose that no machine
re-runs, and the highest-blast-radius first-boot code paths
(partitioning, filesystem creation, bootloader handoff) are the least
tested ones.

This also matters for [RFC-0002](0002-package-integration/README.md):
its model has packages listed in a host's Ignition config and installed
at first boot by apm — that flow lands on exactly the first-boot path
this RFC puts under test.

## Goal

One CI-run fleet test, `checks.fleet.install`, whose script is the
installation guide: every command in it is one a new user would run,
covering all five steps. The operator doc and the test cannot drift,
because the doc's command sequence is checked against (or generated
from) the test.

## Design

A two-node fleet test modeled on `tests/fleet/apm-registry-upgrade.nix`:

- **Node A** (existing boot path): runs the `aos-registry-server` package,
  publishing a package and a newer system generation to a registry +
  binary cache reachable over the fleet L2.
- **Node B** (new boot path): boots the raw server image under OVMF —
  UEFI firmware → sd-boot → UKI → initrd → Ignition — with an Ignition
  config delivered over `-fw_cfg name=opt/com.coreos/config`, no
  metadata ISO attached. The config is the one from
  `docs/boot/qemu-uefi.md`: resize `root-a`, create
  `root-b`/`swap`/`var`, format filesystems, plus the registry trust
  anchor and hostname via the files stage.

The script asserts the provisioned layout (first runtime assertions of
`ignition-disks`, the GPT fixup, and `aos-growfs`), then runs the
porcelain sequence: `apm update` → `apm install <pkg>` →
`apm upgrade --system` → reboot → verify the new generation is active.

### Work items

**1. EDK2/OVMF as an AOS package** — the one large item. The hermetic
rule forbids the host-nixpkgs OVMF that `docs/boot/qemu-uefi.md` uses
for development. Prerequisites `nasm` and `acpica` (for `iasl`) are not
yet in `pkgs/`; both are small autotools/make builds. Then
`pkgs/boot/edk2.nix` builds BaseTools (C + the existing `python3`) and
OvmfPkg, producing `OVMF_CODE.fd` + `OVMF_VARS.fd`. Expected friction:
shebang patching, BaseTools' host assumptions, and vendored submodule
deps (brotli, openssl) that must be fetched as explicit sources.

**2. Full Ignition profile opt-in in the harness.**
`lib/testing/metadata.nix` hardcodes `allowStorageHardware = false`;
parameterize it so a test can opt into the full profile.
`lib/formats/ignition.nix` already supports both;
`checks.ignition-format` already proves the full profile accepts
`storage.disks`/`storage.filesystems` and keeps the restrictive
default pinned. No format changes needed.

**3. Image-boot mode in the test driver and fleet harness.**
`aos_test_driver/qemu.py` gains a machine variant that boots from a
disk image instead of `-kernel`/`-initrd`: two `-drive if=pflash`
entries (read-only `OVMF_CODE.fd`, per-run writable copy of
`OVMF_VARS.fd`), the prepared image as the boot drive, and `-fw_cfg`
for the Ignition config. Critically this node attaches **no metadata
ISO** — the ISO short-circuits platform detection to `file`; without
it, DMI yields `qemu` and Ignition reads fw_cfg. `lib/testing/fleet.nix`
extends the per-machine schema so a node declares `bootImage` +
firmware instead of kernel/initrd. Disk prep (copy, `truncate -s 40G`,
`sgdisk -e` to relocate the GPT backup header) happens where the driver
already makes its per-run disk copy; `gptfdisk` is already packaged.

**4. Driving the installed node.** Fleet tests talk to guests through
the serial test agent baked into the system, which a stock image lacks.
Decision: compose the test's image from the server system plus the
existing test-agent role — the boot and provisioning path stays fully
stock (UEFI → sd-boot → UKI → Ignition disks/files); only the package
set gains the agent. The alternative (driving over SSH via the
Ignition-provisioned key, as `driverInteractive` does interactively) is
purer but requires new scripted-assertion plumbing; it can come later
without changing the test's shape.

**5. The test: `tests/fleet/install-from-image.nix`**, wired as
`checks.fleet.install` in `default.nix`. Assertions in order:

1. node B reaches `multi-user.target` from the UEFI image boot;
2. partition layout matches the declared config — `root-a` grown,
   `root-b`/`swap`/`var` created, `/var` mounted by partlabel;
3. `apm update` pulls metadata from node A's registry;
4. `apm install <pkg>` installs and the package runs;
5. `apm upgrade --system` stages the new generation; after reboot the
   new generation is active and the installed package survives.

**6. Docs alignment.** Promote the flow to an operator install guide
whose command sequence matches the test script one-for-one; note in
`docs/boot/qemu-uefi.md` that the flow is CI-enforced.

### Sequencing

Two parallel tracks that converge at the end:

- **Track 1 (packaging):** `nasm` → `acpica` → `edk2`/OVMF.
- **Track 2 (harness):** metadata profile opt-in → driver/fleet
  image-boot mode → the test, developed against host OVMF locally
  (never merged that way).

Converge by pointing the test's firmware at `pkgs.edk2`, then docs.

## Alternatives considered

- **A dedicated installer porcelain** (`apm bootstrap`, partition/format
  subcommands): rejected. It duplicates what Ignition's declarative
  disks stage already does, adds a second provisioning surface to keep
  consistent, and diverges from the image-based model the cloud
  platforms (and RFC-0002's first-boot package install) assume.
- **Direct kernel boot for the install node** (skip OVMF): rejected.
  It would test the disks stage but silently skip the bootloader
  handoff (sd-boot → UKI) that every real user's first boot depends on
  — the point is to boot the artifact we ship, the way it ships.
- **Testing the disks stage via the ISO/`file` platform**: workable for
  partitioning alone, but it leaves the qemu/fw_cfg platform path — the
  one the operator doc and cloud-adjacent flows use — untested, and
  still requires work items 2 and 5. Not worth the narrower coverage.

## Implementation notes

What the build-out surfaced (decisions and discovered bugs):

- **EDK2 sourcing**: fixed-output archives pin the EDK2 revision and every
  top-level gitlink, and the unpack phase assembles the source tree before the
  build. OVMF compiles vendored submodule sources (openssl, brotli, mipisyst)
  directly, so the root release archive alone is insufficient. Archive
  derivations keep restricted evaluation network-free and avoid fetching
  irrelevant nested Git histories such as upstream test repositories. Build
  quirks are documented in `pkgs/boot/edk2.nix` (CRLF line endings in
  `tools_def.template` being the sneakiest).
- **Driver protocol bug, fixed in `agent.py`**: QEMU drops chardev
  bytes written while the guest's virtio-serial port is closed during
  early boot, so the old held-connection readiness handshake could
  overcount "replies owed" and never declare the agent ready (observed
  as a deadlocked post-reboot wait with the agent demonstrably
  answering). `_wait_ready_qemu` now probes with a fresh connection
  per attempt and keeps the first connection that proves a quiet 1:1
  stream.
- **No merged `/usr/bin` on the image**: production images resolve
  tools by store path, so exposed package units must carry an explicit
  `Environment=PATH=` (see `pkgs/tests/aos-test-agent.nix`) and the
  shared agent script appends the inherited PATH after the FHS dirs.
- **`/dev/console` is tty0 on the image** (`console=tty0` is last on
  the UKI cmdline) — anything that wants to be seen on the serial
  harness log must write `/dev/ttyS0` explicitly.
- **CI sizing**: the test uses a 16 GiB sparse disk with a 6 GiB A/B
  layout (same shape and labels as the documented 40 GiB production
  layout); reboot-to-agent-ready measured ~30 s.

## Open questions

- **Secure Boot**: `sbsigntools` is already packaged; signing the UKI
  and enrolling keys in OVMF vars is a natural follow-on, out of scope
  here.
