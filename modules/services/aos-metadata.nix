##! modules/services/aos-metadata.nix — the `aos metadata` agent (RFC-0011 CS8)
##!
##! Additive, opt-in (`aos.provisioning.metadataAgent.enable`, default false)
##! initrd units that replace Ignition's *fetch* layer with the transport-only
##! `aos metadata` agent (a Rust subcommand in `pkgs.aos`). With the flag off
##! nothing is emitted and the existing Ignition flow is byte-identical.
##!
##! The agent is **transport-only**: it fetches and stashes the *untrusted*
##! operator `host.nix` (+ detached signature) and instance facts into
##! `/run/aos-metadata/`; signature verification is deferred to the stage-2
##! `aos-eval.service` where the `trusted-config-keys.d` anchors live in the
##! measured `/etc`. A failed/missing fetch leaves no `host.nix`, so eval falls
##! through to gen-0-only config — the failure-safe path.
##!
##! Three units, mirroring the Ignition graph (modules/services/ignition.nix):
##!   aos-metadata-detect   (replaces aos-platform-detect): DMI/ISO → platform.env
##!   aos-metadata-network  (replaces aos-ignition-network): DHCP gate, cloud-only
##!   aos-metadata-fetch    (replaces ignition-fetch): platform → stash
##!
##! Phase A coexistence: these run alongside Ignition rather than deleting it;
##! the cutover (deleting ignition-{fetch,disks,mount,files}) lands once each
##! native path has a fleet-green test (see docs/rfcs/0011 provisioning.md).
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.provisioning.metadataAgent;
in {
  options.aos.provisioning.metadataAgent = {
    enable =
      lib.mkEnableOption "the RFC-0011 `aos metadata` transport-only fetch agent";

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

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.aos.config.evalAtBoot.enable;
        message = "aos.provisioning.metadataAgent.enable requires aos.config.evalAtBoot.enable so fetched host configuration is authenticated and evaluated.";
      }
    ];

    boot.initrd.systemd.services = {
      # 1. Platform detection + offline config-drive probe. Absorbs
      #    aos-platform-detect: ports the DMI/SMBIOS decision table and probes
      #    blkid -L {aos-metadata,cidata,config-2}. Writes platform.env (+ the
      #    adjacent need-network flag for cloud platforms).
      "aos-metadata-detect" = {
        description = "AOS metadata platform detection (RFC-0011)";
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

      # 3. Fetch + stash the untrusted user-data + facts. Transport-only: no
      #    signature is verified here. SuccessExitStatus=0 1 keeps a failed
      #    fetch from wedging boot — the absent host.nix makes stage-2 a no-op.
      "aos-metadata-fetch" = {
        description = "Fetch + stash untrusted operator host.nix + instance facts (RFC-0011)";
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
