# Image-boot testing

Most fleet tests boot guests with direct kernel boot. Tests that exercise the
installation path, Secure Boot, measured boot, or recovery instead boot the
real raw image under UEFI firmware, the same way a machine boots the shipped
artifact: OVMF, systemd-boot, UKI, systemd initrd. AOS has no installer
program; installing is writing the image and letting first boot carve the
remaining storage with `systemd-repart`.

The harness lives in `lib/testing/fleet.nix`, `lib/testing/fleet-spec.nix`,
and the Python driver under `pkgs/tools/aos/aos-test-driver/aos_test_driver/`.

## Machine shape

`QemuMachine` (`qemu.py`) supports `boot = "kernel"` and `boot = "image"`.
An image-boot machine:

- copies the image to a per-run disk, grows it sparsely to `disk_size_mib`,
  and runs `sgdisk -e` so the backup GPT header moves to the new end and
  `systemd-repart` sees the full capacity;
- copies `OVMF_VARS` to a per-run writable file, so enrolled keys persist
  across that machine's reboots and nothing leaks between runs;
- runs `-machine q35,smm=on` with the secure-pflash and
  `ICH9-LPC.disable_s3=1` globals that SMM firmware requires, `OVMF_CODE` as
  read-only pflash unit 0 and the vars copy as unit 1;
- may attach an `aos-metadata` ISO as a SCSI CD-ROM to exercise first-boot
  provisioning input, or an `fw_cfg` blob.

## vTPM lifecycle

A machine with `tpm = true` gets a per-machine `swtpm` with persistent state,
connected through `-tpmdev emulator` and `-device tpm-tis`, plus a
`virtio-rng-pci` device so first-boot key generation does not drain the
software TPM's slow random-number path.

swtpm exits when QEMU disconnects, and a relaunched swtpm loading the
previous boot's state wedges the next measured boot. TPM machines therefore
omit `-no-reboot` and reset in place: QEMU and swtpm stay up, NV state and
keys persist, and PCRs reset at power-on as on real hardware. Non-TPM
machines keep `-no-reboot`, which makes a guest reboot exit QEMU; the Secure
Boot tamper test relies on that exit as the rejection signal.

An in-place reset keeps the agent socket open, so a reply from the old boot
could look like the new boot answering. Reboot handling calls `wait_down`
until the agent stops responding before `wait_ready` waits for the new boot.

For PCR 12 tests the driver can relaunch the same disk, vars, and vTPM state
with a chosen set of SMBIOS Type 11 strings
(`relaunch_with_smbios_oem_strings`), so firmware-supplied boot input is
tested rather than simulated inside the guest.

## Agent readiness

Guests are driven over a virtio-serial agent port. While the guest port is
closed during firmware and early kernel boot, QEMU can drop bytes written to
the chardev. A long-lived connection would then count replies it is still
owed for dropped pings and never declare the guest ready. `_wait_ready_qemu`
(`agent.py`) instead probes with a fresh connection and one `PING` per
attempt and keeps the first connection that answers.

## Image quirks the tests account for

- Images have no merged `/usr/bin`; tools resolve by store path. Units for
  exposed packages, including the test agent, carry an explicit
  `Environment=PATH=`.
- The image test fixtures bundle `aos-test-agent`
  (`aos.packages.aos-test-agent.bundle = true`), which production server
  images leave out. The boot and provisioning path stays otherwise stock.

## Checks

| Check | Exercises |
| --- | --- |
| `checks.fleet.install-from-image` | Raw image boot, `systemd-repart` layout, `apm update` and `install` against a registry peer, `apm image upgrade` into the inactive slot, reboot, and commit |
| `checks.fleet.secure-boot`, `checks.fleet.secure-boot-lockdown` | [Secure Boot](secure-boot.md) |
| `checks.fleet.measured-boot` | [Measured boot](measured-boot.md) and [Recovery](recovery.md) |

Image-boot tests need KVM, as all VM tests do.
