##! modules/services/aos-metadata.nix — the `aos metadata` agent
##!
##! Initrd units for the native `aos metadata` agent. Every AOS system carries
##! this provisioning path.
##!
##! Fetch stores exact user-data and facts under `/run/aos-metadata/`.
##! Authorization then applies the measured `platform` or `signed` policy and
##! is the only step allowed to produce exact `host.nix`. Restricted initrd
##! evaluation projects `aos.provisioning`; full evaluation remains in stage 2.
##!
##! Units implement state detection, acquisition, authorization, and projection:
##!   aos-provisioning-state durable GPT marker → storage mutation gate
##!   aos-metadata-detect   DMI/ISO → platform.env
##!   aos-metadata-network  DHCP gate, cloud-only
##!   aos-metadata-fetch    platform → stash
##!   aos-metadata-network-seed rendered seed → mounted gen-0 /var/etc
##!   aos-metadata-authorize trust → exact host.nix
##!   aos-provisioning-eval restricted Nix → validated transient repart.d
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
    aos.boot.initrd.extraPackages = [
      configTrustAnchors
      config.aos.config.evalAtBoot.baseLib
      pkgs.nix
    ];

    boot.initrd.systemd.services = {
      "aos-provisioning-state" = {
        description = "Detect durable first-boot provisioning state";
        wantedBy = ["initrd-root-fs.target"];
        before = [
          "aos-metadata-detect.service"
          "aos-metadata-fetch.service"
          "aos-metadata-authorize.service"
          "aos-provisioning-eval.service"
        ];
        requires = [
          "systemd-udevd.service"
          "systemd-udev-trigger.service"
        ];
        after = [
          "systemd-udevd.service"
          "systemd-udev-trigger.service"
          "systemd-udev-settle.service"
        ];
        unitConfig.DefaultDependencies = "no";
        environment.PATH = lib.makeBinPath [pkgs.coreutils pkgs.systemd];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -u
          udevadm settle || true
          if [ -e /dev/disk/by-partlabel/aos-provenance-operator-v1 ] \
            || [ -e /dev/disk/by-partlabel/aos-provenance-fallback-v1 ]; then
            mkdir -p ${cfg.stashDir}
            : > ${cfg.stashDir}/provisioned
          fi
        '';
      };

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
          "aos-provisioning-state.service"
          "systemd-udevd.service"
          "systemd-udev-trigger.service"
        ];
        after = [
          "aos-provisioning-state.service"
          "systemd-udevd.service"
          "systemd-udev-trigger.service"
        ];
        unitConfig.DefaultDependencies = "no";
        environment = {
          AOS_METADATA_BLKID = "${pkgs.util-linux}/sbin/blkid";
          AOS_METADATA_MOUNT = "${pkgs.util-linux}/bin/mount";
          PATH = lib.makeBinPath [
            pkgs.coreutils
            pkgs.util-linux
          ];
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        script = ''
          if ${pkgs.aos}/bin/aos metadata detect; then
            exit 0
          fi
          if [ -e ${cfg.stashDir}/provisioned ]; then
            echo "aos-metadata: detection failed after provisioning; continuing with the active runtime generation" >&2
            exit 0
          fi
          exit 1
        '';
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
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        script = ''
          if ${pkgs.aos}/bin/aos metadata fetch; then
            exit 0
          fi
          if [ -e ${cfg.stashDir}/provisioned ]; then
            echo "aos-metadata: fetch failed after provisioning; continuing with the active runtime generation" >&2
            exit 0
          fi
          exit 1
        '';
      };

      # Fetch must precede repart because host.nix owns the storage plan, while
      # /var cannot be mounted until repart completes. Keep that dependency
      # acyclic by rendering the static-network seed into the initrd stash in
      # aos-metadata-fetch, then copy it into the mounted persistent lower here.
      # etc-overlay-setup subsequently exposes the seed to stage-2 networkd.
      "aos-metadata-network-seed" = {
        description = "Seed DHCP-less metadata networking into gen-0 /var/etc";
        wantedBy = ["initrd-fs.target"];
        requires = [
          "aos-metadata-fetch.service"
          "mount-var.service"
        ];
        after = [
          "aos-metadata-fetch.service"
          "mount-var.service"
        ];
        before = [
          "etc-overlay-setup.service"
          "initrd-fs.target"
        ];
        unitConfig = {
          DefaultDependencies = "no";
          ConditionPathExists = "${cfg.stashDir}/network/10-aos-seed.network";
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        script = ''
          ${pkgs.coreutils}/bin/install -D -m 0644 \
            ${cfg.stashDir}/network/10-aos-seed.network \
            /sysroot/var/etc/systemd/network/10-aos-seed.network
        '';
      };

      # 4. Apply the trust policy to the exact fetched host.nix bytes.
      "aos-metadata-authorize" = {
        description = "Authorize exact first-boot host.nix";
        requiredBy = ["initrd-root-fs.target"];
        requires = ["aos-metadata-fetch.service"];
        after = ["aos-metadata-fetch.service"];
        before = [
          "aos-provisioning-eval.service"
          "initrd-root-fs.target"
        ];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        script = ''
          if ${pkgs.aos}/bin/aos metadata authorize \
            --trust ${trust} \
            ${lib.optionalString (trust == "signed") "--trusted-config-keys-dir ${configTrustAnchors}"}; then
            exit 0
          fi
          if [ -e ${cfg.stashDir}/provisioned ]; then
            echo "aos-metadata: authorization failed after provisioning; ignoring the new input" >&2
            exit 0
          fi
          echo "aos-metadata: authorizing ${trust} host.nix failed; refusing first-boot provisioning" >&2
          exit 1
        '';
      };

      # 5. Evaluate only aos.provisioning using the image's ABI-pinned base
      #    library. No package modules, registry, builders, or full runtime
      #    configuration are reachable in this projection.
      "aos-provisioning-eval" = {
        description = "Evaluate and validate one-time host provisioning";
        requiredBy = ["initrd-root-fs.target"];
        requires = ["aos-metadata-authorize.service"];
        after = ["aos-metadata-authorize.service"];
        before = [
          "aos-repart.service"
          "initrd-root-fs.target"
        ];
        unitConfig.DefaultDependencies = "no";
        environment = {
          NIX_CONFIG = "experimental-features = nix-command";
          PATH = lib.makeBinPath [pkgs.nix pkgs.coreutils];
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        script = ''
          committed_arg=""
          if [ -e /dev/disk/by-partlabel/aos-provenance-operator-v1 ]; then
            marker=/dev/disk/by-partlabel/aos-provenance-operator-v1
            marker_uuid=$(${pkgs.util-linux}/bin/lsblk -ndo PARTUUID "$marker")
            committed_arg="--committed-source operator --marker-uuid $marker_uuid"
          elif [ -e /dev/disk/by-partlabel/aos-provenance-fallback-v1 ]; then
            marker=/dev/disk/by-partlabel/aos-provenance-fallback-v1
            marker_uuid=$(${pkgs.util-linux}/bin/lsblk -ndo PARTUUID "$marker")
            committed_arg="--committed-source fallback --marker-uuid $marker_uuid"
          fi

          if [ -e /dev/disk/by-partlabel/aos-provenance-operator-v1 ] \
            && [ ! -e ${cfg.stashDir}/host.nix ]; then
            echo "aos-provisioning: no current authorized host.nix; skipping advisory storage drift evaluation" >&2
            exit 0
          fi

          if ${pkgs.aos}/bin/aos metadata eval-provisioning \
            --base-lib ${config.aos.config.evalAtBoot.baseLib} \
            ${lib.optionalString measured "--measured-boot"} \
            $committed_arg; then
            exit 0
          fi
          if [ -n "$committed_arg" ]; then
            echo "aos-provisioning: current storage intent is invalid or differs from committed provenance; factory reset is required to apply it" >&2
            printf '%s\n' divergent > ${cfg.stashDir}/storage-coherence
            exit 0
          fi
          echo "aos-provisioning: restricted provisioning evaluation failed; refusing first-boot disk mutation" >&2
          exit 1
        '';
      };
    };
  };
}
