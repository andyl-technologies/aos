##! modules/services/aos-metadata.nix — the `aos metadata` agent
##!
##! Initrd units for the native `aos metadata` agent. Every AOS system carries
##! this provisioning path.
##!
##! Fetch stores exact user-data and facts under `/run/aos-metadata/`.
##! Authorization then applies the measured `platform` or `signed` policy and
##! is the only step allowed to produce `host.nix` or transient `repart.d`.
##! Full Nix evaluation remains in stage 2.
##!
##! Four units implement detection, networking, fetch, and authorization:
##!   aos-metadata-detect   DMI/ISO → platform.env
##!   aos-metadata-network  DHCP gate, cloud-only
##!   aos-metadata-fetch    platform → stash
##!   aos-metadata-authorize trust + schema → host.nix + optional repart.d
##!
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.provisioning.metadataAgent;
  trust = config.aos.config.evalAtBoot.trust;
  measured = config.aos.boot.secureBoot.measuredBoot.enable;
  configKeys = config.aos.apm.configKeys;
  configTrustAnchors = pkgs.runCommand "aos-provisioning-trust-anchors" {} ''
    mkdir -p $out
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList (op: keys: ''
        cat > $out/${op}.pub <<'KEYS'
        ${lib.concatStringsSep "\n" keys}
        KEYS
      '')
      configKeys)}
  '';
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
    aos.boot.initrd.extraPackages = [configTrustAnchors];

    boot.initrd.systemd.services = {
      # 1. Platform detection + offline config-drive probe. Applies the
      #    DMI/SMBIOS decision table and probes blkid -L
      #    {aos-metadata,cidata,config-2}. Writes platform.env (+ the
      #    adjacent need-network flag for cloud platforms).
      "aos-metadata-detect" = {
        description = "Detect the metadata platform and configuration drive";
        wantedBy = ["initrd-root-fs.target"];
        before = [
          "aos-metadata-fetch.service"
          "aos-metadata-authorize.service"
        ];
        requires = [
          "systemd-udevd.service"
          "systemd-udev-trigger.service"
        ];
        after = [
          "systemd-udevd.service"
          "systemd-udev-trigger.service"
        ];
        unitConfig.DefaultDependencies = "no";
        environment.PATH = lib.makeBinPath [
          pkgs.coreutils
          pkgs.util-linux
        ];
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

      # 3. Fetch exact user-data + facts. Authorization is a distinct step so
      #    neither stage 2 nor repart can consume a partial acquisition.
      "aos-metadata-fetch" = {
        description = "Fetch operator configuration and instance facts";
        wantedBy = ["initrd-root-fs.target"];
        requires = ["aos-metadata-detect.service"];
        after = [
          "aos-metadata-detect.service"
          "aos-metadata-network.service"
        ];
        before = [
          "aos-metadata-authorize.service"
          "initrd-root-fs.target"
        ];
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

      # 4. Apply the measured trust policy, parse the closed provisioning
      #    schema, content-pin any host.nix URL, and render transient repart
      #    definitions. Unlike fetch, failure is fatal: a possibly declared
      #    storage plan must never silently fall back to the baked layout.
      "aos-metadata-authorize" = {
        description = "Authorize first-boot provisioning input";
        requiredBy = ["initrd-root-fs.target"];
        requires = ["aos-metadata-fetch.service"];
        after = ["aos-metadata-fetch.service"];
        before = [
          "aos-repart.service"
          "initrd-root-fs.target"
        ];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart =
            "${pkgs.aos}/bin/aos metadata authorize"
            + " --trust ${trust}"
            + lib.optionalString (trust == "signed")
            " --trusted-config-keys-dir ${configTrustAnchors}"
            + lib.optionalString measured " --measured-boot";
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
      };
    };
  };
}
