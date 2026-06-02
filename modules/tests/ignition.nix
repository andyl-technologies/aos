##! modules/tests/ignition.nix — Ignition first-boot provisioning end-to-end
##!
##! Exercises the full metadata-delivery path:
##!   1. The harness packs `instanceMetadata.config` into an ISO9660 image
##!      (volume label `aos-metadata`) and attaches it as a SCSI CD-ROM.
##!   2. In the initrd, `aos-platform-detect.service` finds
##!      `/dev/disk/by-label/aos-metadata`, mounts it at `/run/aos-metadata`,
##!      and writes `IGNITION_CONFIG_FILE=/run/aos-metadata/config.json`
##!      to the platform env that every ignition stage inherits.
##!   3. ignition-files runs with `--root=/run/etc/ignition-<gen>`
##!      and writes the file under that per-gen subtree.
##!   4. etc-overlay-setup mounts the per-gen ignition lower as the
##!      middle layer of the /etc overlay (spec v12 §6.1.4), so the
##!      file surfaces at `/etc/<path>` in stage-2.
##!
##! Under the new layer order (`/var/etc > ignition lower > system EROFS`),
##! files the test VM bakes into `/var/etc/<path>` shadow any ignition
##! write to the same `/etc/<path>`. The test therefore writes to a path
##! that lib/testing/vm.nix's varSeed does NOT touch — see the comment
##! on `varSeed` in lib/testing/vm.nix for the seeded set.
{...}: {
  system.checks.ignition-storage-files = {
    description = "ignition first-boot provisioning via ISO9660 metadata channel";
    instanceMetadata = {
      format = "ignition";
      config = {
        ignition.version = "3.5.0";
        storage = {
          files = [
            {
              path = "/etc/aos/ignition-test-marker";
              mode = 420; # 0644
              overwrite = true;
              contents.source = "data:,ignition-files-stage-ran%0A";
            }
          ];
        };
      };
    };
    checks = [
      {
        name = "files-stage-write-visible";
        description = "ignition-files wrote /etc/aos/ignition-test-marker via the per-gen lower";
        script = ''
          assert "ignition-files-stage-ran" in vm.succeed(
              "cat /etc/aos/ignition-test-marker"
          )
        '';
      }
      {
        name = "metadata-iso-survives-switch-root";
        description = "aos-platform-detect's /run/aos-metadata mount survives switch-root into stage-2";
        script = ''
          vm.succeed("findmnt -t iso9660 /run/aos-metadata")
          vm.succeed("test -f /run/aos-metadata/config.json")
        '';
      }
      {
        name = "machine-id-seeded";
        description = "aos-machine-id.service seeded /var/etc/machine-id (spec v12 §6.1.5)";
        script = ''
          # 32 lowercase hex chars + newline = 33 bytes (per
          # `tr -d '-' < /proc/sys/kernel/random/uuid`).
          val = vm.succeed("cat /etc/machine-id")
          assert len(val) == 33, f"expected 32+\\n bytes, got {len(val)}"
          assert all(c in '0123456789abcdef\n' for c in val), \
              f"expected hex+newline, got {val!r}"
        '';
      }
      {
        name = "stage1-network-gate-skipped-on-file-platform";
        description = "the ISO (file) platform leaves the stage-1 network gate condition-skipped — no DHCP pulled in";
        script = ''
          # The aos-metadata ISO ⇒ PLATFORM_ID=file. The detector takes its
          # early-exit branch and never classifies a cloud platform, so the
          # need-network flag is absent and platform.env carries no
          # IGNITION_NEEDS_NETWORK. /run is mount --moved into stage-2, so
          # these initrd artifacts are still readable here.
          vm.fail("test -e /run/ignition/need-network")
          env = vm.succeed("cat /run/ignition/platform.env")
          assert "PLATFORM_ID=file" in env, f"expected file platform, got {env!r}"
          assert "IGNITION_NEEDS_NETWORK" not in env, \
              f"file platform must not flag network, got {env!r}"

          # aos-ignition-network is WantedBy initrd-root-fs.target, so its job
          # is enqueued, but ConditionPathExists=/run/ignition/need-network is
          # unmet ⇒ systemd skips it (and pulls in NO networking). The skip is
          # logged by PID1 with this exact wording (src/core/job.c). It is an
          # initrd-only unit, so this is unambiguously a stage-1 signal even
          # though stage-2 networking runs wait-online later in the same boot.
          boot_journal = vm.succeed("journalctl -b --no-pager")
          assert (
              "skipped, unmet condition check "
              "ConditionPathExists=/run/ignition/need-network" in boot_journal
          ), "aos-ignition-network was not condition-skipped on the file platform"
        '';
      }
    ];
  };
}
