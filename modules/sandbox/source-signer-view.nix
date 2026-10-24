##! modules/sandbox/source-signer-view.nix — Source-only read-only journal view
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.sourceSignerView;
  controller = config.aos.sandbox.controller;
  preparer = import ./_view-preparer.nix {inherit config pkgs;};
  source = "/var/lib/aos/sandbox/source-domains";
  view = "/run/aos/sandbox-source-signer-journal";
  otherUsers = builtins.attrValues (lib.filterAttrs (name: _: name != "aos-source-signer") config.aos.users.users);
  otherGroups = builtins.attrValues (lib.filterAttrs (name: _: name != "aos-source-signer") config.aos.users.groups);
  prepareView = preparer.writeScript "aos-sandbox-source-signer-view" ''
    set -eu

    controller_uid=${toString controller.uid}
    controller_gid=${toString controller.gid}
    signer_uid=${toString cfg.uid}
    signer_gid=${toString cfg.gid}

    require_root_directory() {
      test ! -L "$1"
      test "$(${preparer.coreutils}/stat --format='%F:%u:%g' "$1")" = directory:0:0
      mode="$(${preparer.coreutils}/stat --format='%a' "$1")"
      test $((8#$mode & 022)) -eq 0
      # The signer needs original root metadata, but no access inside it.
      test $((8#$mode & 001)) -ne 0
    }

    for directory in /var /var/lib /var/lib/aos /var/lib/aos/sandbox /run /run/aos; do
      if ! test -e "$directory"; then
        ${preparer.coreutils}/mkdir --mode=0755 "$directory"
      fi
      require_root_directory "$directory"
    done

    test ! -L ${source}
    if ! test -e ${source}; then
      ${preparer.coreutils}/mkdir --mode=0700 ${source}
      ${preparer.coreutils}/chown "$controller_uid:$controller_gid" ${source}
    fi
    test "$(${preparer.coreutils}/stat --format='%F:%u:%g:%a' ${source})" = \
      "directory:$controller_uid:$controller_gid:700"
    for entry in ${source}/* ${source}/.[!.]* ${source}/..?*; do
      if ! test -e "$entry" && ! test -L "$entry"; then
        continue
      fi
      case "$entry" in
        ${source}/source-domains-v1.journal|\
        ${source}/source-domains-v1.journal.lock|\
        ${source}/source-domains-v1.journal.compact.tmp) ;;
        *) exit 1 ;;
      esac
      test ! -L "$entry"
      test "$(${preparer.coreutils}/stat --format='%F:%u:%g:%a:%h' "$entry")" = \
        "regular file:$controller_uid:$controller_gid:600:1"
    done

    test ! -L ${view}
    if ! test -e ${view}; then
      ${preparer.coreutils}/mkdir --mode=0700 ${view}
    fi
    test "$(${preparer.coreutils}/stat --format='%F:%u:%g:%a' ${view})" = directory:0:0:700
    if ${preparer.utilLinux}/findmnt --mountpoint ${view} --noheadings >/dev/null; then
      exit 1
    fi

    ${preparer.utilLinux}/mount --internal-only --no-mtab --bind \
      --map-users "$controller_uid:$signer_uid:1" \
      --map-groups "$controller_gid:$signer_gid:1" \
      --options ro,nosuid,nodev,noexec,nosymfollow \
      ${source} ${view}
    trap '${preparer.utilLinux}/umount --internal-only --no-mtab --no-canonicalize ${view}' EXIT

    test "$(${preparer.coreutils}/stat --format='%d:%i' ${source})" = \
      "$(${preparer.coreutils}/stat --format='%d:%i' ${view})"
    test "$(${preparer.coreutils}/stat --format='%F:%u:%g:%a' ${view})" = \
      "directory:$signer_uid:$signer_gid:700"
    options="$(${preparer.utilLinux}/findmnt --noheadings --mountpoint ${view} --output VFS-OPTIONS)"
    for option in ro nosuid nodev noexec nosymfollow; do
      case ",$options," in
        *,$option,*) ;;
        *) exit 1 ;;
      esac
    done
    trap - EXIT
  '';
in {
  options.aos.sandbox.sourceSignerView = {
    _preparerPackage = lib.mkOption {
      type = lib.types.package;
      internal = true;
      readOnly = true;
      default = prepareView;
      description = "Exact immutable checked source view entrypoint selected by the production policy.";
    };
    enable = lib.mkEnableOption "the separate Source signer read-only journal view";

    uid = lib.mkOption {
      type = lib.types.int;
      default = 814;
      description = "Dedicated Source signer UID exposed only through its read-only view.";
    };

    gid = lib.mkOption {
      type = lib.types.int;
      default = 814;
      description = "Dedicated Source signer GID exposed only through its read-only view.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.aos.sandbox.policyAuthority.enable && config.aos.sandbox.controllerService.enable;
        message = "Source signer view requires the policy authority and Controller services";
      }
      {
        assertion = cfg.uid > 0 && cfg.uid < 65536 && lib.all (user: user.uid != cfg.uid) otherUsers;
        message = "Source signer UID must be distinct from every installed user";
      }
      {
        assertion = cfg.gid > 0 && cfg.gid < 65536 && lib.all (group: group.gid != cfg.gid) otherGroups;
        message = "Source signer GID must be distinct from every installed group";
      }
    ];

    aos.users.users.aos-source-signer = {
      uid = cfg.uid;
      group = "aos-source-signer";
      home = "/";
      shell = "/sbin/nologin";
      description = "AOS Source hold readback signer identity";
      extraGroups = [];
    };
    aos.users.groups.aos-source-signer = {
      gid = cfg.gid;
      members = [];
    };

    systemd.services.aos-sandbox-source-signer-view = {
      description = "AOS Source signer-only idmapped journal view";
      wantedBy = ["multi-user.target"];
      requires = ["aos-sandbox-cache-journal-view.service"];
      after = ["local-fs.target" "aos-sandbox-cache-journal-view.service"];
      before = ["aos-sandboxd.service" "aos-sandbox-source-signerd.service" "aos-sandbox-policy-authorityd.service"];
      unitConfig.RequiresMountsFor = ["/var/lib/aos/sandbox"];
      serviceConfig =
        preparer.serviceConfig
        // {
          Type = "oneshot";
          RemainAfterExit = true;
          SELinuxContext = lib.mkIf preparer.confined "system_u:system_r:aos_sandbox_source_view_preparer_t";
          ExecStart = "${prepareView}/bin/aos-sandbox-source-signer-view";
          ExecStop = "${preparer.utilLinux}/umount --internal-only --no-mtab --no-canonicalize ${view}";
          User = "root";
          Group = "root";
          UMask = "0077";
          CapabilityBoundingSet = [
            "CAP_CHOWN"
            "CAP_DAC_READ_SEARCH"
            "CAP_SETGID"
            "CAP_SETUID"
            "CAP_SYS_ADMIN"
          ];
          RestrictAddressFamilies = ["AF_UNIX"];
        };
    };
  };
}
