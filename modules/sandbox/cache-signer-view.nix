##! modules/sandbox/cache-signer-view.nix — narrow Cache signer readback mounts
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.cacheSignerView;
  controller = config.aos.sandbox.controller;
  journalSource = "/var/lib/aos/sandbox/cache-residency-journals";
  objectSource = "/var/lib/aos/sandbox/cache-residency-objects";
  journalView = "/run/aos/sandbox-cache-signer-journals";
  objectView = "/run/aos/sandbox-cache-signer-objects";
  otherUsers = builtins.attrValues (lib.filterAttrs (name: _: name != "aos-cache-signer") config.aos.users.users);
  otherGroups = builtins.attrValues (lib.filterAttrs (name: _: name != "aos-cache-signer") config.aos.users.groups);
  prepareViews = pkgs.writeShellScriptBin "aos-sandbox-cache-signer-views" ''
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
      # The signer must stat original Cache root names without entering them.
      test $((8#$mode & 001)) -ne 0
    }

    for directory in /var /var/lib /var/lib/aos /var/lib/aos/sandbox /run /run/aos; do
      if ! test -e "$directory"; then
        ${pkgs.coreutils}/bin/mkdir --mode=0755 "$directory"
      fi
      require_root_directory "$directory"
    done

    # No old parent is needed on a fresh install. Its presence could later
    # hide Controller-created state behind a name the signer cannot traverse.
    legacy=/var/lib/aos/sandbox/cache-residency
    test ! -e "$legacy" && test ! -L "$legacy"

    test ! -L ${journalSource}
    test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a' ${journalSource})" = \
      "directory:$controller_uid:$controller_gid:700"
    for entry in ${journalSource}/* ${journalSource}/.[!.]* ${journalSource}/..?*; do
      if ! test -e "$entry" && ! test -L "$entry"; then
        continue
      fi
      case "$entry" in
        ${journalSource}/state.journal|${journalSource}/state.journal.lock|${journalSource}/state.journal.compact.tmp|\
        ${journalSource}/authority.journal|${journalSource}/authority.journal.lock|${journalSource}/authority.journal.compact.tmp|\
        ${journalSource}/clock.journal|${journalSource}/clock.journal.lock|${journalSource}/clock.journal.compact.tmp|\
        ${journalSource}/policy-hold.journal|${journalSource}/policy-hold.journal.lock|${journalSource}/policy-hold.journal.compact.tmp) ;;
        *) exit 1 ;;
      esac
      test ! -L "$entry"
      test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a:%h' "$entry")" = \
        "regular file:$controller_uid:$controller_gid:600:1"
    done

    if test -L ${objectSource}; then
      exit 1
    fi
    if ! test -e ${objectSource}; then
      ${pkgs.coreutils}/bin/mkdir --mode=0700 ${objectSource}
      ${pkgs.coreutils}/bin/chown "$controller_uid:$controller_gid" ${objectSource}
    fi
    test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a' ${objectSource})" = \
      "directory:$controller_uid:$controller_gid:700"
    for name in .owner.lock owner-state; do
      entry=${objectSource}/$name
      if test -e "$entry" || test -L "$entry"; then
        test ! -L "$entry"
        test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a:%h' "$entry")" = \
          "regular file:$controller_uid:$controller_gid:600:1"
      fi
    done

    for view in ${journalView} ${objectView}; do
      test ! -L "$view"
      if ! test -e "$view"; then
        ${pkgs.coreutils}/bin/mkdir --mode=0700 "$view"
      fi
      test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a' "$view")" = directory:0:0:700
      if ${pkgs.util-linux}/bin/findmnt --mountpoint "$view" --noheadings >/dev/null; then
        exit 1
      fi
    done

    ${pkgs.util-linux}/bin/mount --bind \
      --map-users "$controller_uid:$signer_uid:1" \
      --map-groups "$controller_gid:$signer_gid:1" \
      --options ro,nosuid,nodev,noexec,nosymfollow \
      ${journalSource} ${journalView}
    trap '${pkgs.util-linux}/bin/umount --no-canonicalize ${journalView}' EXIT
    ${pkgs.util-linux}/bin/mount --bind \
      --map-users "$controller_uid:$signer_uid:1" \
      --map-groups "$controller_gid:$signer_gid:1" \
      --options ro,nosuid,nodev,noexec,nosymfollow \
      ${objectSource} ${objectView}
    trap '${pkgs.util-linux}/bin/umount --no-canonicalize ${objectView}; ${pkgs.util-linux}/bin/umount --no-canonicalize ${journalView}' EXIT

    for pair in '${journalSource}:${journalView}' '${objectSource}:${objectView}'; do
      source="''${pair%%:*}"
      view="''${pair#*:}"
      test "$(${pkgs.coreutils}/bin/stat --format='%d:%i' "$source")" = \
        "$(${pkgs.coreutils}/bin/stat --format='%d:%i' "$view")"
      test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a' "$view")" = \
        "directory:$signer_uid:$signer_gid:700"
      options="$(${pkgs.util-linux}/bin/findmnt --noheadings --mountpoint "$view" --output VFS-OPTIONS)"
      for option in ro nosuid nodev noexec nosymfollow; do
        case ",$options," in
          *,$option,*) ;;
          *) exit 1 ;;
        esac
      done
    done
    trap - EXIT
  '';
  stopViews = pkgs.writeShellScriptBin "aos-sandbox-cache-signer-views-stop" ''
    status=0
    ${pkgs.util-linux}/bin/umount --no-canonicalize ${objectView} || status=1
    ${pkgs.util-linux}/bin/umount --no-canonicalize ${journalView} || status=1
    exit "$status"
  '';
in {
  options.aos.sandbox.cacheSignerView = {
    enable = lib.mkEnableOption "the read-only idmapped Cache signer journal and object views";

    uid = lib.mkOption {
      type = lib.types.int;
      default = 813;
      description = "Dedicated Cache signer UID exposed only through its read-only idmapped views.";
    };

    gid = lib.mkOption {
      type = lib.types.int;
      default = 813;
      description = "Dedicated Cache signer GID exposed only through its read-only idmapped views.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.aos.sandbox.policyAuthority.enable && config.aos.sandbox.controllerService.enable;
        message = "Cache signer views require the policy authority and Controller services";
      }
      {
        assertion = cfg.uid > 0 && cfg.uid < 65536 && lib.all (user: user.uid != cfg.uid) otherUsers;
        message = "Cache signer UID must be distinct from every installed user";
      }
      {
        assertion = cfg.gid > 0 && cfg.gid < 65536 && lib.all (group: group.gid != cfg.gid) otherGroups;
        message = "Cache signer GID must be distinct from every installed group";
      }
    ];

    aos.users.users.aos-cache-signer = {
      uid = cfg.uid;
      group = "aos-cache-signer";
      home = "/";
      shell = "/sbin/nologin";
      description = "AOS Cache readback signer identity";
      extraGroups = [];
    };
    aos.users.groups.aos-cache-signer = {
      gid = cfg.gid;
      members = [];
    };

    systemd.services.aos-sandbox-cache-signer-views = {
      description = "AOS Cache signer-only idmapped readback views";
      wantedBy = ["multi-user.target"];
      requires = ["aos-sandbox-cache-journal-view.service"];
      after = ["aos-sandbox-cache-journal-view.service"];
      before = ["aos-sandboxd.service" "aos-sandbox-policy-authorityd.service"];
      unitConfig = {
        BindsTo = ["aos-sandbox-cache-journal-view.service"];
        RequiresMountsFor = ["/var/lib/aos/sandbox"];
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${prepareViews}/bin/aos-sandbox-cache-signer-views";
        ExecStop = "${stopViews}/bin/aos-sandbox-cache-signer-views-stop";
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
