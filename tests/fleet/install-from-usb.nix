# tests/fleet/install-from-usb.nix - Unattended bare-metal installation from USB.
#
# Each machine starts with a blank virtio disk and a removable USB stick
# holding installer media built from its own system:
#
#   target:  host.nix on the stick's AOS-META partition opts into unattended
#            installation onto /dev/disk/by-id/virtio-aos-install-target.
#            OVMF falls through the blank disk to the stick, the installer
#            initrd authorizes and evaluates host.nix, verifies the db-signed
#            payload, writes the release image, sets BootNext, and reboots.
#            The installed system's first boot then reads the same host.nix
#            from the still-attached stick and provisions storage.
#   refused: host.nix omits the opt-in. The installer must stop with a
#            console diagnostic before touching the disk, and never reboot.
#
# Both machines carry a vTPM: the measured-boot image needs one, and it makes
# QEMU reset in place on the installer's reboot instead of exiting.
{
  lib,
  mkSystem,
  pkgs,
}: let
  targetDevice = "/dev/disk/by-id/virtio-aos-install-target";

  system = mkSystem [
    ../../systems/server-verity.nix
    ../../systems/_server-test-packages.nix
    {
      aos.image.budgets.maxRootMiB = 640;
    }
  ];
in {
  name = "install-from-usb";
  # The installer decompresses, writes, and reads back the full image before
  # the installed system's first boot partitions and formats storage.
  timeout = 3000;
  bootTimeout = 1500;
  systemReadyTimeout = 300;

  machines = {
    target = {
      inherit system;
      bootMode = "installer";
      imageDiskMiB = 16384;
      packages = ["aos-test-agent"];
      memoryMiB = 4096;
      tpm = true;
      metadata."host.nix" = ''
        {
          aos.provisioning.install = {
            mode = "unattended";
            targetDevice = "${targetDevice}";
          };
          aos.provisioning.storage.partitions.var.sizeMin = "6G";
        }
      '';
    };

    refused = {
      inherit system;
      bootMode = "installer";
      imageDiskMiB = 16384;
      memoryMiB = 4096;
      tpm = true;
      expectAgent = false;
      metadata."host.nix" = ''
        {
          aos.provisioning.storage.partitions.var.sizeMin = "6G";
        }
      '';
    };
  };

  testScript =
    # python
    ''
      import json
      import time
      from pathlib import Path

      # ════ Installed system ════════════════════════════════════════════
      # The agent handshake already proves the installer wrote the disk and
      # handed the next boot to it: the agent only exists in the release image.
      target.succeed("systemctl is-active multi-user.target")

      # The immutable root comes from the installed virtio disk, not the stick.
      root_source = target.succeed("findmnt -no SOURCE /").strip()
      assert root_source == "/dev/mapper/root", root_source
      layout = json.loads(target.succeed(
          "lsblk --json -o NAME,PARTLABEL,TYPE ${targetDevice}"
      ))
      labels = {
          child.get("partlabel")
          for child in layout["blockdevices"][0].get("children", [])
      }
      for label in ["ESP", "root-a", "root-a-hash", "root-b", "root-b-hash", "var", "swap"]:
          assert label in labels, (label, labels)
      assert "aos-provenance-operator-v1" in labels, labels

      # First boot provisioned storage from the stick's host.nix.
      audit = json.loads(target.succeed("cat /var/lib/aos-provisioning/audit.json"))
      assert audit["source"] == "operator", audit
      var_bytes = int(target.succeed(
          "lsblk -bno SIZE /dev/disk/by-partlabel/var"
      ).strip())
      assert var_bytes >= 6 * 1024 ** 3, var_bytes

      # The stick is still attached and unchanged: one AOS-META device, and
      # the payload partition was never written by the installed system.
      target.succeed("test \"$(blkid -c /dev/null -o device -t LABEL=AOS-META | wc -l)\" = 1")
      target.succeed("test -b /dev/disk/by-partlabel/aos-payload")
      target.fail("blkid -c /dev/null -o device -t PARTLABEL=ESP | grep -v \"$(readlink -f ${targetDevice})\"")

      # ════ Refused installation ════════════════════════════════════════
      serial_log = Path(refused.serial_log_path)
      deadline = time.monotonic() + 900
      transcript = ""
      expected = "does not enable unattended installation"
      while time.monotonic() < deadline:
          if serial_log.exists():
              transcript = serial_log.read_text(errors="replace")
              if expected in transcript:
                  break
          time.sleep(2)
      assert expected in transcript, transcript[-8000:]
      assert "no reboot will occur" in transcript, transcript[-8000:]
      assert "writing the release image" not in transcript, transcript[-8000:]
      assert "erasing the target disk in" not in transcript, transcript[-8000:]
      assert "Switching root" not in transcript, transcript[-8000:]
    '';
}
