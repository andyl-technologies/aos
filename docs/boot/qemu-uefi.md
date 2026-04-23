# Booting the AOS server image under UEFI (systemd-boot + UKI)

Operator-facing instructions for the systemd-boot + UKI boot path. The
image is self-bootable — no `-kernel`/`-initrd`/`-append` on the QEMU
command line. UEFI firmware loads sd-boot from the ESP, sd-boot
auto-discovers the UKI in `EFI/Linux/`, the UKI hands off to the
kernel + initrd, and ignition provisions the disk on first boot.

Supersedes `2026-04-16_initrd_vm_qemu_instructions.md`.

## 0. Ignition test config

Write to `tests/ignition-test.json` at the repo root. Not checked in.

```json
{
  "ignition": { "version": "3.4.0" },
  "storage": {
    "disks": [
      {
        "device": "/dev/vda",
        "wipeTable": false,
        "partitions": [
          { "number": 2, "label": "root-a", "sizeMiB": 16384, "resize": true,
            "typeGuid": "0FC63DAF-8483-4772-8E79-3D69D8477DE4" },
          { "number": 3, "label": "root-b", "sizeMiB": 16384,
            "typeGuid": "0FC63DAF-8483-4772-8E79-3D69D8477DE4" },
          { "number": 4, "label": "swap",   "sizeMiB": 4096,
            "typeGuid": "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" },
          { "number": 5, "label": "var",    "sizeMiB": 0 }
        ]
      }
    ],
    "filesystems": [
      { "device": "/dev/disk/by-partlabel/root-b", "format": "ext4",
        "label": "aos-root-b", "wipeFilesystem": false },
      { "device": "/dev/disk/by-partlabel/var",   "format": "ext4",
        "label": "aos-var",   "wipeFilesystem": false }
    ],
    "files": [
      { "path": "/var/etc/hostname",    "mode": 420, "overwrite": true,
        "contents": { "source": "data:,aos-test-server" } },
      { "path": "/var/etc/machine-id",  "mode": 420, "overwrite": true,
        "contents": { "source": "data:,b5a2f1c8e6d04a3f9b7e2d1c8a5f3e7d" } },
      { "path": "/var/etc/ssh/authorized_keys/root", "mode": 384,
        "overwrite": true,
        "contents": { "source": "data:;base64,REPLACE_ME_RUN_ssh-add_-L_pipe_base64_-w0" } }
    ]
  }
}
```

Layout after first boot:

| # | Label | Size | Purpose |
|---|---|---|---|
| 1 | ESP (label unset by GPT spec; filesystem label `ESP`) | 512 MiB | unchanged from image |
| 2 | root-a | 16 GiB | grew from sized-to-fit → 16 GiB via `resize=true` |
| 3 | root-b | 16 GiB | new, empty ext4 (future sysupdate target) |
| 4 | swap | 4 GiB | typeGuid is the Linux swap GUID |
| 5 | var | remaining | ext4 for `/var` |

Disk size requirement: at least 40 GiB (16 + 16 + 4 + change + GPT overhead).

Replace the authorized_keys `source` with `data:;base64,$(ssh-add -L | base64 -w0)`.

## 1. Build

```sh
nix build -L .#server-image-raw
```

Produces:

- `result/aos-aos.img` — raw GPT disk, self-bootable under UEFI.
- `result/image-info.json` — metadata (ESP contents, partition layout).

No standalone `vmlinuz`/`initrd.img` symlinks — the image is
self-contained. (If direct-kernel-boot is ever needed, use
`system.config.system.build.{kernel,initrd}` directly, not the image.)

## 2. Prepare a writable disk

```sh
cp result/aos-aos.img /tmp/kal/tmp/aos-vm.img
chmod u+w /tmp/kal/tmp/aos-vm.img
truncate -s 40G /tmp/kal/tmp/aos-vm.img
nix-shell -p gptfdisk --run "sgdisk -e /tmp/kal/tmp/aos-vm.img"
```

`sgdisk -e` relocates the GPT backup header to the end of the 40 GiB disk
so ignition's partition creation succeeds beyond the original boundary.

## 3. Prepare OVMF (UEFI firmware)

OVMF is not an AOS package (EDK2 is large; we rely on the host's Nix
store for development). Snapshot the vars file to a writable copy per VM:

```sh
OVMF=$(nix-build '<nixpkgs>' -A OVMF.fd --no-out-link)
cp $OVMF/FV/OVMF_VARS.fd /tmp/kal/tmp/aos-vm-OVMF_VARS.fd
chmod u+w /tmp/kal/tmp/aos-vm-OVMF_VARS.fd
```

## 4. Launch QEMU

```sh
nix-shell -p qemu --run "qemu-system-x86_64 \
  -machine q35,accel=kvm \
  -cpu host \
  -m 4096 \
  -smp 2 \
  -display gtk \
  -drive if=pflash,format=raw,readonly=on,file=$OVMF/FV/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=/tmp/kal/tmp/aos-vm-OVMF_VARS.fd \
  -drive file=/tmp/kal/tmp/aos-vm.img,format=raw,if=virtio \
  -fw_cfg name=opt/com.coreos/config,file=$(pwd)/tests/ignition-test.json \
  -nic user,model=virtio-net-pci,hostfwd=tcp::2222-:22 \
  -chardev socket,id=ttyS0,path=/tmp/kal/tmp/aos-vm-ttyS0.sock,server=on,wait=off,logfile=/tmp/kal/tmp/aos-vm-ttyS0.log \
  -serial chardev:ttyS0 \
  -qmp unix:/tmp/kal/tmp/aos-vm-qmp.sock,server=on,wait=off"
```

Notable flags:

- **No `-kernel`/`-initrd`/`-append`.** UEFI firmware reads the ESP,
  invokes `BOOTX64.EFI`, sd-boot lists entries from `EFI/Linux/`, picks
  `aos-<version>.efi`, the UKI bootstraps the kernel + initrd. The
  cmdline is embedded in the UKI; QEMU never sees it on the command line.
- **Two `-drive if=pflash`** entries (OVMF code + vars).
- **`-fw_cfg name=opt/com.coreos/config,...`** delivers the ignition
  config. The guest's `aos-platform-detect.service` auto-detects `qemu`
  from DMI, and ignition reads the config through the same fw_cfg
  channel as before.

## 5. Interacting with the guest

Talk to `ttyS0` from the host:

```sh
# Interactive session. Ctrl+] (0x1d) detaches without killing the guest.
nix-shell -p socat --run \
  "socat -,rawer,escape=0x1d UNIX-CONNECT:/tmp/kal/tmp/aos-vm-ttyS0.sock"

# Script a command and tail the serial log for the response.
: > /tmp/kal/tmp/aos-vm-ttyS0.log
nix-shell -p socat --run \
  "printf 'systemctl --failed\n' | \
   socat -t 5 - UNIX-CONNECT:/tmp/kal/tmp/aos-vm-ttyS0.sock"
tail -c 4000 /tmp/kal/tmp/aos-vm-ttyS0.log
```

Graceful shutdown via QMP:

```sh
nix-shell -p socat --run "{ \
  printf '%s\n' '{\"execute\": \"qmp_capabilities\"}' \
                '{\"execute\": \"system_powerdown\"}'; \
  sleep 2; \
} | socat -t 5 - UNIX-CONNECT:/tmp/kal/tmp/aos-vm-qmp.sock"
```

Force-quit if the guest isn't responding:

```sh
nix-shell -p socat --run "{ \
  printf '%s\n' '{\"execute\": \"qmp_capabilities\"}' \
                '{\"execute\": \"quit\"}'; \
} | socat -t 2 - UNIX-CONNECT:/tmp/kal/tmp/aos-vm-qmp.sock"
```

SSH in once ignition has run (the `authorized_keys/root` line in §0's
ignition config authorizes your key):

```sh
ssh -p 2222 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null root@127.0.0.1
```

## 6. Bare-metal via ISO metadata (smoke-test path)

To rehearse the bare-metal flow in QEMU:

1. **Build a metadata ISO.** Flake output `.#server-image-metadata-iso`
   wraps `mkMetadataIso` (defined in `lib/testing/vm.nix`) around a
   hand-written ignition config. Produces `result/metadata.iso` with
   volume label `aos-metadata`.

2. **Attach alongside the disk.** QEMU gets an extra SCSI CD-ROM (so
   the guest sees a natural optical device, matching the IPMI
   virtual-media experience):

   ```
   -drive id=metadata,file=result/metadata.iso,if=none,format=raw,readonly=on \
   -device scsi-cd,drive=metadata,bus=scsi0.0 \
   -device virtio-scsi-pci,id=scsi0
   ```

3. **Remove** the `-fw_cfg name=opt/com.coreos/config` line from the
   launch command so fw_cfg doesn't shortcut detection (otherwise the
   DMI branch would still select `qemu` and ignition would read from
   fw_cfg, bypassing the ISO).

**What happens at boot.** `aos-platform-detect.service` finds
`/dev/disk/by-label/aos-metadata` before checking DMI. It mounts the
ISO at `/run/aos-metadata` and writes `/run/ignition/platform.env`
with `PLATFORM_ID=file` and
`IGNITION_CONFIG_FILE=/run/aos-metadata/config.json`. The ignition
stage units pick those up via `EnvironmentFile=`, and ignition's
`file` provider reads `config.json` directly from the mounted ISO.
No HTTP, no socket, no localhost — the entire flow is local reads.

## 7. Re-runs and cleanup

After any rebuild — the ESP / UKI layout or cmdline may have changed,
and OVMF variables from a previous run may point at stale boot entries:

```sh
# Shut down (QMP system_powerdown or quit — see §5).

# Remove stale sockets and logs.
rm -f /tmp/kal/tmp/aos-vm-ttyS0.sock /tmp/kal/tmp/aos-vm-qmp.sock
rm -f /tmp/kal/tmp/aos-vm-ttyS0.log

# Reset OVMF vars. A stale VARS.fd can carry UEFI boot entries that
# reference the previous ESP's EFI/Linux/aos-<old-version>.efi path,
# which no longer exists, leaving sd-boot on the recovery screen.
cp "$OVMF/FV/OVMF_VARS.fd" /tmp/kal/tmp/aos-vm-OVMF_VARS.fd
chmod u+w /tmp/kal/tmp/aos-vm-OVMF_VARS.fd

# Re-init the disk (ignition needs a fresh canvas if partition layout
# shifted between image builds).
cp result/aos-aos.img /tmp/kal/tmp/aos-vm.img
chmod u+w /tmp/kal/tmp/aos-vm.img
truncate -s 40G /tmp/kal/tmp/aos-vm.img
nix-shell -p gptfdisk --run "sgdisk -e /tmp/kal/tmp/aos-vm.img"

# Relaunch per §4.
```

## 8. Smoke-test success criteria

A successful end-to-end smoke test produces ALL of the following in
the guest:

1. **SSH reachable** on host port 2222 with the authorized key from
   `tests/ignition-test.json` — `ssh -p 2222 root@127.0.0.1 true`
   returns 0.
2. **No failed units** — `systemctl --failed` lists nothing.
3. **Platform correctly detected** —
   `journalctl -u aos-platform-detect.service` shows the service
   succeeded and `/run/ignition/platform.env` was last written with
   `PLATFORM_ID=qemu` (fw_cfg path) or `PLATFORM_ID=file` (ISO path
   from §6).
4. **Ignition succeeded and saw the env file** — `ps` finds no
   ignition process, `/var/etc/.ignition-result.json` is present, and
   `journalctl -u ignition-fetch.service` confirms the platform
   matches what the detector chose. Cross-check the env propagation:
   `systemctl show ignition-fetch.service -p Environment` lists
   `IGNITION_CONFIG_FILE` when running the §6 ISO flow.
5. **Growfs ran and root-a filled its partition** —
   `systemctl status aos-growfs.service` shows `active (exited)`, and
   `df -BG --output=size / | tail -1` reports ≥ 15 GiB (partition is
   16 GiB; ext4 overhead accounts for the rest).
6. **Ignition layout intact** — `lsblk -o NAME,LABEL,SIZE /dev/vda`
   shows partitions `ESP`, `root-a` (16 GiB), `root-b` (16 GiB),
   `swap` (4 GiB), `var` (~4 GiB).
7. **sd-boot booted the expected UKI** — `bootctl status` (run in
   stage-2, sd-boot records the loaded image) shows `Current Boot
   Loader: systemd-boot` and `Default Boot Loader Entry:
   aos-<version>.efi`.

Capture `journalctl -b -o short-iso > /tmp/kal/tmp/aos-vm-boot.log`
for the archive.

## 9. Gotchas

- **`result/aos-aos.img` is a read-only symlink into the Nix store**
  (perms `r--r--r--`). Passing it directly as `-drive file=` yields
  "Permission denied" on some QEMU builds even with `snapshot=on`.
  Always `cp` it out (§2).
- **Ignition requires the disk to be bigger than the image.** §0's
  ignition config needs ~36 GiB of unallocated space to create root-b
  (16 GiB), swap (4 GiB), and `/var` (remainder). The `truncate -s 40G`
  + `sgdisk -e` in §2 gives it that room. Less than that and ignition
  aborts with "not enough space".
- **OVMF boot entries are persistent across VM runs.** UEFI firmware
  stores boot entries in `OVMF_VARS.fd`. A stale vars file can keep
  pointing at `EFI/Linux/aos-<old-version>.efi` from the previous
  image, leaving sd-boot on the recovery screen after you rebuild.
  Always refresh the vars snapshot on each run (§7).
- **`-display gtk` opens a graphical window for `tty1`.** Drop it and
  add `-nographic` for headless runs. Keep in mind the debug profile
  auto-logs in root on `tty1`, which is only visible through the Gtk
  window — scripted tests interact via ttyS0 (§5).
- **Connect to the serial socket *before* the VM reaches
  multi-user.target** or you'll miss the early boot log. The
  `logfile=` option on the `-chardev socket` entry persists everything
  to `/tmp/kal/tmp/aos-vm-ttyS0.log`, so post-hoc inspection is still
  possible — but live debugging of an ignition failure needs a
  concurrent `socat` session.
- **`systemd.gpt-auto=0` is mandatory** in the baked-in UKI cmdline.
  Without it, systemd-gpt-auto-generator synthesises `.swap` /
  `.mount` units at boot with `ExecStart=/usr/sbin/swapon` — a path
  AOS's rootfs doesn't populate. Already in `aos.boot.kernelParams`
  defaults; don't remove it.
