##! modules/services/aos-metadata.nix — the `aos metadata` agent
##!
##! Initrd units for the transport-only `aos metadata` agent (a Rust subcommand
##! in `pkgs.aos`). Every AOS system carries this provisioning path.
##!
##! The agent is **transport-only**: it fetches and stashes the
##! operator `host.nix` (+ detached signature) and instance facts into
##! `/run/aos-metadata/`. The default policy trusts metadata delivered by the
##! deployment platform. Deployments using the signed policy defer signature
##! verification to `aos-eval.service`, where the trust anchors live in the
##! measured `/etc`. A failed or missing fetch leaves no `host.nix`, so the
##! baked configuration remains active.
##!
##! Three units implement detection, conditional networking, and metadata fetch:
##!   aos-metadata-detect   DMI/ISO → platform.env
##!   aos-metadata-network  DHCP gate, cloud-only
##!   aos-metadata-fetch    platform → stash
##!
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.provisioning.metadataAgent;
in {
  options.aos.provisioning.metadataAgent = {
    stashDir = lib.mkOption {
      type = lib.types.str;
      default = "/run/aos-metadata";
      internal = true;
      readOnly = true;
      description = ''
        Initrd stash directory (read-only). A child of `/run` so it survives
        `mount --move /run /sysroot/run` during switch_root and is staged into
        the evaluator root `/run/aos-eval/` by stage-2. This path is **hardcoded
        in the `aos metadata` binary** (`DetectOptions`/`FetchOptions::default`),
        so it is fixed here rather than configurable — a different value would
        only mis-point the `EnvironmentFile`/`ConditionPathExists` without moving
        where the binary actually writes.
      '';
    };
  };

  config = {
    boot.initrd.systemd.services = {
      # 1. Platform detection + offline config-drive probe. Absorbs
      #    aos-platform-detect: ports the DMI/SMBIOS decision table and probes
      #    blkid -L {aos-metadata,cidata,config-2}. Writes platform.env (+ the
      #    adjacent need-network flag for cloud platforms).
      "aos-metadata-detect" = {
        description = "Detect the metadata platform and configuration drive";
        wantedBy = ["initrd-root-fs.target"];
        before = ["aos-metadata-fetch.service"];
        requires = [
          "systemd-udevd.service"
          "systemd-udev-trigger.service"
        ];
        after = [
          "systemd-udevd.service"
          "systemd-udev-trigger.service"
        ];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.aos}/bin/aos metadata detect";
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
      };

      # 2. Bring up DHCP, cloud platforms only. detect drops
      #    <stashDir>/need-network for network-dependent platforms; the
      #    ConditionPathExists makes this a no-op (pulling in nothing) on the
      #    offline/local channels. SuccessExitStatus keeps a wait-online
      #    timeout best-effort rather than wedging boot.
      "aos-metadata-network" = {
        description = "Bring up networking for the aos metadata agent (cloud platforms only)";
        wantedBy = ["initrd-root-fs.target"];
        requires = ["aos-metadata-detect.service"];
        after = ["aos-metadata-detect.service"];
        before = ["aos-metadata-fetch.service"];
        unitConfig = {
          DefaultDependencies = "no";
          ConditionPathExists = "${cfg.stashDir}/need-network";
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.systemd}/bin/systemctl start network-online.target";
          SuccessExitStatus = "0 1";
        };
      };

      # 3. Fetch + stash user-data + facts. Transport-only: no signature is
      #    verified here. SuccessExitStatus=0 1 keeps a failed
      #    fetch from wedging boot — the absent host.nix makes stage-2 a no-op.
      "aos-metadata-fetch" = {
        description = "Fetch operator configuration and instance facts";
        wantedBy = ["initrd-root-fs.target"];
        requires = ["aos-metadata-detect.service"];
        after = [
          "aos-metadata-detect.service"
          "aos-metadata-network.service"
        ];
        before = ["initrd-root-fs.target"];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          EnvironmentFile = "${cfg.stashDir}/platform.env";
          ExecStart = "${pkgs.aos}/bin/aos metadata fetch";
          SuccessExitStatus = "0 1";
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
      };
    };
  };
}
