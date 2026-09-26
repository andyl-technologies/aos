##! modules/sandbox/source-signer-view.nix — Source-only read-only journal view
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.sourceSignerView;
  controller = config.aos.sandbox.controller;
  source = "/var/lib/aos/sandbox/source-domains";
  view = "/run/aos/sandbox-source-signer-journal";
  otherUsers = builtins.attrValues (lib.filterAttrs (name: _: name != "aos-source-signer") config.aos.users.users);
  otherGroups = builtins.attrValues (lib.filterAttrs (name: _: name != "aos-source-signer") config.aos.users.groups);
  prepareView = pkgs.writeShellScriptBin "aos-sandbox-source-signer-view" ''
    set -eu

    controller_uid=${toString controller.uid}
    controller_gid=${toString controller.gid}
    signer_uid=${toString cfg.uid}
    signer_gid=${toString cfg.gid}

    require_root_directory() {
      test ! -L "$1"
      test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g' "$1")" = directory:0:0
      mode="$(${pkgs.coreutils}/bin/stat --format='%a' "$1")"
      test $((8#$mode & 022)) -eq 0
      # The signer needs original root metadata, but no access inside it.
      test $((8#$mode & 001)) -ne 0
    }

    for directory in /var /var/lib /var/lib/aos /var/lib/aos/sandbox /run /run/aos; do
      if ! test -e "$directory"; then
        ${pkgs.coreutils}/bin/mkdir --mode=0755 "$directory"
      fi
      require_root_directory "$directory"
    done

    test ! -L ${source}
    if ! test -e ${source}; then
      ${pkgs.coreutils}/bin/mkdir --mode=0700 ${source}
      ${pkgs.coreutils}/bin/chown "$controller_uid:$controller_gid" ${source}
    fi
    test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a' ${source})" = \
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
      test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a:%h' "$entry")" = \
        "regular file:$controller_uid:$controller_gid:600:1"
    done

    test ! -L ${view}
    if ! test -e ${view}; then
      ${pkgs.coreutils}/bin/mkdir --mode=0700 ${view}
    fi
    test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a' ${view})" = directory:0:0:700
    if ${pkgs.util-linux}/bin/findmnt --mountpoint ${view} --noheadings >/dev/null; then
      exit 1
    fi

    ${pkgs.util-linux}/bin/mount --bind \
      --map-users "$controller_uid:$signer_uid:1" \
      --map-groups "$controller_gid:$signer_gid:1" \
      --options ro,nosuid,nodev,noexec,nosymfollow \
      ${source} ${view}
    trap '${pkgs.util-linux}/bin/umount --no-canonicalize ${view}' EXIT

    test "$(${pkgs.coreutils}/bin/stat --format='%d:%i' ${source})" = \
      "$(${pkgs.coreutils}/bin/stat --format='%d:%i' ${view})"
    test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a' ${view})" = \
      "directory:$signer_uid:$signer_gid:700"
    options="$(${pkgs.util-linux}/bin/findmnt --noheadings --mountpoint ${view} --output VFS-OPTIONS)"
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
      after = ["local-fs.target"];
      before = ["aos-sandboxd.service" "aos-sandbox-source-signerd.service" "aos-sandbox-policy-authorityd.service"];
      unitConfig.RequiresMountsFor = ["/var/lib/aos/sandbox"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${prepareView}/bin/aos-sandbox-source-signer-view";
        ExecStop = "${pkgs.util-linux}/bin/umount --no-canonicalize ${view}";
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
