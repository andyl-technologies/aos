##! modules/security/ebpf-lsm.nix — Fleet BPF-LSM policy loader.
##!
##! Loads BPF-LSM policy artifacts selected by `/etc/aos/policy.toml`. The
##! loader resolves selected policies through the system package profile so the
##! BPF object and JSON policy come from installed, signed package metadata.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.security.ebpfLsm;
  # The bpffs-prep script is an image-fixed artifact (a pure
  # function of pkgs, not host.nix). Reference the resolved artifact so the
  # on-host eval-only evaluator uses the stage-1-frozen store path instead of
  # rebuilding it; `pkgs.writeShellScriptBin` is absent from the stage-2 frozen
  # pkgs. On a normal build `frozenArtifacts` is empty, so this resolves to the
  # same derivation as before (byte-identical).
  prepareBpffs = config.aos.config.artifacts.ebpf-lsm-prepare-bpffs;
in {
  options.aos.security.ebpfLsm = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to load fleet BPF-LSM policies selected by
        `/etc/aos/policy.toml`.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Register the bpffs-prep script as an image-fixed config artifact
    # Guarded so the on-host frozen pkgs (which lacks
    # `writeShellScriptBin`) never evaluates the builder; the resolved
    # `artifacts.ebpf-lsm-prepare-bpffs` reads the frozen path in that case.
    aos.config._artifactSources.ebpf-lsm-prepare-bpffs =
      if config.aos.config.frozenArtifacts ? "ebpf-lsm-prepare-bpffs"
      then null
      else
        pkgs.writeShellScriptBin "aos-prepare-ebpf-lsm-bpffs" ''
          set -eu
          ${pkgs.coreutils}/bin/mkdir -p /sys/fs/bpf
          if ! ${pkgs.util-linux}/bin/mountpoint -q /sys/fs/bpf; then
            ${pkgs.util-linux}/bin/mount -t bpf bpf /sys/fs/bpf
          fi
          ${pkgs.coreutils}/bin/mkdir -p /sys/fs/bpf/aos/lsm
        '';

    # The policy package rides in via aos's runtimeDeps (AOS_EBPF_LSM_POLICY),
    # so it need not be on PATH.
    systemd.services.aos-ebpf-lsm-policies = {
      description = "Load AOS fleet BPF-LSM policies";
      wantedBy = ["multi-user.target"];
      before = ["multi-user.target"];
      after = [
        "local-fs.target"
        "aos-seed-baked-packages.service"
        "aos-install-baked-packages.service"
      ];
      unitConfig.ConditionPathExists = "/etc/aos/policy.toml";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStartPre = "${prepareBpffs}/bin/aos-prepare-ebpf-lsm-bpffs";
        ExecStart = "${pkgs.aos.packageRuntime}/bin/aos-package-runtime _load-ebpf-lsm-policies --system";
        CapabilityBoundingSet = "CAP_BPF CAP_SYS_ADMIN CAP_SYS_RESOURCE";
        AmbientCapabilities = "";
        LimitMEMLOCK = "infinity";
        NoNewPrivileges = false;
        PrivateDevices = true;
        DevicePolicy = "closed";
        PrivateNetwork = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadWritePaths = "/sys/fs/bpf";
        RestrictAddressFamilies = "AF_UNIX";
        RestrictNamespaces = true;
        MemoryDenyWriteExecute = true;
        SystemCallFilter = "@system-service mount umount2 bpf";
        SystemCallErrorNumber = "EPERM";
      };
    };
  };
}
