##! modules/services/boot-substrate.nix — Neutral first-boot substrate
##!
##! The provisioning-backend-agnostic initrd units that assemble the running
##! system on first boot, regardless of who carves the disk or delivers the
##! per-generation `/etc`:
##!
##!   - `mount-var.service`         — mounts the /var partition before the
##!                                    /etc overlay and profile seeding
##!   - `etc-overlay-setup.service` — the three-layer /etc overlay
##!                                    (/var/etc + per-gen files lower + system
##!                                    EROFS metadata)
##!   - `nix-overlay-setup.service` — the /nix overlay (writable upper on /var)
##!   - `aos-seed-profiles.service` — seeds apm's system-profile state.json
##!   - `run-etc-setup.service`     — the /run/etc tmpfs the overlay lives on
##!   - `aos-machine-id.service`    — seeds /var/etc/machine-id
##!
##! These order against `aos-repart.service` and the on-host config-generation
##! seed (`aos-config-seed.service`). Repart is idempotent when `/var` already
##! exists.
{
  config,
  pkgs,
  lib,
  ...
}: let
  # The neutral units shell out to a small toolset: `mount`/`mountpoint`
  # (util-linux), `mkdir`/`ln`/`tr` (coreutils), and `jq` (aos-seed-profiles
  # assembles apm's initial state.json). sbin lookups are covered by the
  # `lib.makeSearchPath "sbin"` side.
  bootTools = [
    pkgs.kmod
    pkgs.util-linux
    pkgs.systemd
    pkgs.coreutils
    pkgs.bash
    pkgs.jq
    pkgs.tpm2-tools
  ];
  bootPath = lib.concatStringsSep ":" [
    (lib.makeBinPath bootTools)
    (lib.makeSearchPath "sbin" bootTools)
  ];

  # `systemd-repart` carves and grows the substrate before the neutral boot
  # units consume it. It is idempotent when /var is already present.
  disksUnit = "aos-repart.service";

  # The files backend is always the on-host config-gen seed
  # (modules/base/config-seed.nix), which scaffolds the empty per-generation
  # /etc lower; subsequent generations are rendered by the stage-2 config-eval
  # fixpoint and switched in by `activate`.
  filesUnit = "aos-config-seed.service";

  # The neutral boot-infrastructure units are always emitted and ordered
  # against `disksUnit` and `filesUnit`.
  neutralBootServices = {
    # Best-effort wait-online: succeed as soon as ANY managed link is
    # routable. Without --any the default "all links online" wedges ~90 s
    # whenever a second NIC is managed but has no DHCP server (e.g. the
    # fleet test's mcast NIC). overrideStrategy=asDropin emits only a
    # <unit>.d/overrides.conf over the upstream unit symlinked by the
    # builder; the empty-then-set ExecStart list is the systemd reset idiom.
    "systemd-networkd-wait-online" = {
      overrideStrategy = "asDropin";
      serviceConfig.ExecStart = [
        ""
        "${pkgs.systemd}/lib/systemd/systemd-networkd-wait-online --any"
      ];
    };

    # The [Install] symlinks ride in the system EROFS image
    # (via environment.etc."systemd/system" and the composefs dump
    # script's directory recursion at spec v12 §5.2) and in the
    # per-gen config lower (via generated storage.links,
    # spec v12 §5.6). The runtime preset-walker is
    # sufficient.

    # Mount the /var partition created by the disks backend so that the
    # files backend can write to /sysroot/var/etc/* and the mount
    # persists through switch-root into stage-2 (no ExecStop).
    # Stage-2 systemd sees the existing mount and considers its
    # fstab-generated var.mount unit already active.
    "mount-var" = {
      description = "Mount /var Partition";
      requiredBy = ["initrd-fs.target"];
      before = [
        filesUnit
        "etc-overlay-setup.service"
        "initrd-fs.target"
      ];
      requires = ["sysroot.mount"] ++ lib.optional (disksUnit != null) disksUnit;
      after =
        ["sysroot.mount"]
        ++ lib.optional (disksUnit != null) disksUnit
        ++ ["systemd-udev-settle.service"];
      unitConfig = {
        ConditionPathExists = "/dev/disk/by-partlabel/var";
      };
      environment.PATH = bootPath;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      script = ''
        set -euo pipefail
        if ! mountpoint -q /sysroot/var; then
          mkdir -p /sysroot/var
          # When measured boot seals /var (RFC-0006 phase 3), the
          # aos-var-crypt service runs first and exposes the unlocked
          # LUKS volume as /dev/mapper/var; mount that. Otherwise the
          # raw partition is mounted directly (unchanged behaviour).
          if [ -e /dev/mapper/var ]; then
            mount -o nosuid,nodev /dev/mapper/var /sysroot/var
          else
            mount -o nosuid,nodev /dev/disk/by-partlabel/var /sysroot/var
          fi
        fi
        # Standard /var subdirectories expected by systemd and daemons.
        mkdir -p /sysroot/var/{log,lib,tmp}
        # /var/etc is the host-persistent allowlist of the /etc
        # overlay (spec v12 §5.4) — created eagerly so
        # aos-machine-id and sshd-keygen find it on first boot.
        mkdir -p /sysroot/var/etc
        # /var/run → /run is the modern-Linux convention; many daemons
        # (dbus, various PID files) still reference /var/run paths.
        ln -sfn /run /sysroot/var/run
      '';
    };

    # /etc overlay (spec v12 §6.1.4) — three-layer composition:
    #
    #   lowerdir+=/var/etc                      — host-persistent allowlist
    #                                             (machine-id, ssh host keys)
    #   lowerdir+=/run/etc/config-<gen>/etc   — per-gen configuration lower
    #                                             (empty initial seed)
    #   lowerdir+=/run/etc/system-<gen>/metadata — system EROFS (composefs)
    #   datadir+= /run/etc/system-<gen>/content  — basedir for octal-mode
    #                                              entries (metacopy)
    #   upperdir = /run/etc/upper-<gen>/dir      — runtime writes (tmpfs-backed)
    #
    # The immutable toplevel of the image that actually booted is read from
    # `/sysroot/aos-toplevel`. The config-generation pointer is deliberately
    # not used for the bottom lower: after an A/B transition it may still name
    # a child of the previous image until first-boot re-evaluation commits.
    "etc-overlay-setup" = {
      description = "Set Up /etc Overlay Filesystem";
      wantedBy = ["initrd-fs.target"];
      before = [
        "initrd-fs.target"
        "initrd-switch-root.target"
      ];
      requires = [
        "sysroot.mount"
        "mount-var.service"
        filesUnit
        "aos-seed-profiles.service"
        "run-etc-setup.service"
        "nix-overlay-setup.service"
        "aos-machine-id.service"
      ];
      after = [
        "sysroot.mount"
        "mount-var.service"
        filesUnit
        "aos-seed-profiles.service"
        "run-etc-setup.service"
        "nix-overlay-setup.service"
        "aos-machine-id.service"
        "initrd-root-fs.target"
      ];
      unitConfig.DefaultDependencies = "no";
      environment.PATH = bootPath;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        set -euo pipefail
        . /run/aos-profile-gen.env

        # Resolve the active toplevel at runtime; do NOT bake
        # ${"\${config.system.build.toplevel}"} into this script
        # (initrd→toplevel→initrd cycle). nix-overlay-setup mounts
        # /sysroot/nix as the merged overlay, so /sysroot$toplevel
        # resolves through that.
        toplevel=$(readlink /sysroot/aos-toplevel)
        gen=$AOS_PROFILE_GEN
        # Per-gen mountpoints live under the initrd's own /run/etc
        # (the tmpfs that run-etc-setup.service mounted before
        # this unit runs). systemd-initrd does `mount --move /run
        # /sysroot/run` during switch_root, which carries the
        # /run/etc sub-mounts into stage-2 unchanged. Placing them
        # on /sysroot/run/etc instead would make /run/etc a sibling
        # of the moved /run rather than a child of it, so the
        # moved /run would shadow the whole subtree post-pivot.
        sys=/run/etc/system-$gen
        config_lower=/run/etc/config-$gen
        upper_root=/run/etc/upper-$gen

        mkdir -p "$sys/metadata" "$sys/content" \
                 "$upper_root/dir" "$upper_root/work"
        # $config_lower/etc already exists from aos-config-seed.service.

        # $toplevel is a /nix/store/... path; prefix /sysroot
        # because the real root is still under /sysroot in the
        # initrd. /sysroot/nix is the merged overlay (set up by
        # nix-overlay-setup.service, which we ordered After).
        #
        # `etc-basedir` and `etc-metadata.erofs` are symlinks inside
        # the toplevel that point at other /nix/store/... paths.
        # `mount --bind` follows those symlinks, but the resolved
        # /nix/store/... target isn't reachable from PID 1's
        # process root in the initrd — only /sysroot/nix/store/
        # is. Read the symlinks ourselves and prefix /sysroot so
        # the bind sources resolve in the initrd's view.
        basedir=$(readlink "/sysroot$toplevel/etc-basedir")
        metadata=$(readlink "/sysroot$toplevel/etc-metadata.erofs")
        ${pkgs.util-linux}/bin/mount --bind \
          "/sysroot$basedir" "$sys/content"
        ${pkgs.util-linux}/bin/mount -t erofs -o ro,nodev,nosuid \
          "/sysroot$metadata" "$sys/metadata"

        # /sysroot/var/etc keeps its /sysroot prefix because /var is
        # mounted on /sysroot/var in stage-1; the overlay records
        # vfsmount refs at mount time, so the literal source string
        # in the option line never gets re-resolved post-pivot.
        ${pkgs.util-linux}/bin/mount -t overlay overlay -o \
          nodev,nosuid,metacopy=on,redirect_dir=on,lowerdir+=/sysroot/var/etc,lowerdir+=$config_lower/etc,lowerdir+=$sys/metadata,datadir+=$sys/content,upperdir=$upper_root/dir,workdir=$upper_root/work \
          /sysroot/etc

        # Inspection symlinks (relative targets so they survive
        # switch_root). Created under the initrd's /run/etc so they
        # move into stage-2 along with the rest of /run.
        ln -sfn system-$gen   /run/etc/system
        ln -sfn config-$gen /run/etc/config
        ln -sfn upper-$gen    /run/etc/upper

        # Both readers have run; drop the gen-handoff file so it
        # doesn't ride mount --move into stage-2 with a stale value.
        rm -f /run/aos-profile-gen.env
      '';
    };

    # /nix overlay: stack a writable upper on /var over the image's
    # immutable /nix.lower so the Nix package manager can install new
    # store paths at runtime. The image builder ships /nix.lower
    # populated and /nix as an empty mountpoint (lib/build/rootfs.nix),
    # so this unit is unconditional — no first-boot rename, no
    # remount,rw window, identical on fresh installs and post-upgrade
    # boots.
    #
    # Once the Nix DB is seeded, GC safety depends on roots. The lower
    # filesystem cannot be physically deleted, but unreferenced lower store
    # paths can still be hidden by overlay whiteouts; the stage-2 GC-root
    # bridge keeps the live AOS profile closure reachable.
    "nix-overlay-setup" = {
      description = "Set Up /nix Overlay Filesystem";
      wantedBy = ["initrd-fs.target"];
      before = [
        "initrd-fs.target"
        "initrd-switch-root.target"
      ];
      requires = [
        "sysroot.mount"
        "mount-var.service"
      ];
      after = [
        "sysroot.mount"
        "mount-var.service"
        "initrd-root-fs.target"
      ];
      environment.PATH = bootPath;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        set -euo pipefail
        sysroot=/sysroot

        # Upper and work must share a filesystem (overlayfs requires
        # workdir to be on the same fs as upperdir for atomic
        # rename-into-upper). Both live on the /var partition.
        mkdir -p "$sysroot/var/lib/nix-overlay/upper"
        mkdir -p "$sysroot/var/lib/nix-overlay/work"

        if ! mountpoint -q "$sysroot/nix"; then
          ${pkgs.util-linux}/bin/mount -t overlay overlay \
            -o nosuid,nodev,lowerdir="$sysroot/nix.lower",upperdir="$sysroot/var/lib/nix-overlay/upper",workdir="$sysroot/var/lib/nix-overlay/work" \
            "$sysroot/nix"
        fi
      '';
    };

    # Seed apm system-profile state on first boot. Reads the
    # toplevel path from `/sysroot/aos-toplevel` (the seed pointer
    # the rootfs ships at lib/build/rootfs.nix) rather than
    # interpolating `${config.system.build.toplevel}` directly —
    # the initrd builder's closure scan
    # (modules/base/_initrd-builder.nix) would otherwise drag the
    # toplevel into the initrd's closure and create a cycle
    # (toplevel ships the initrd). Spec v12 §6.1.1, §6.1.
    "aos-seed-profiles" = {
      description = "Seed apm system-profile state on first boot";
      wantedBy = ["initrd-fs.target"];
      before = [
        filesUnit
        "run-etc-setup.service"
        "aos-machine-id.service"
        "initrd-fs.target"
      ];
      requires = [
        "sysroot.mount"
        "mount-var.service"
        "nix-overlay-setup.service"
      ];
      after = [
        "sysroot.mount"
        "mount-var.service"
        "nix-overlay-setup.service"
      ];
      unitConfig.DefaultDependencies = "no";
      environment.PATH = bootPath;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        set -euo pipefail
        profile_dir=/sysroot/var/lib/profiles/system
        image_dir=/sysroot/var/lib/profiles/image

        # The seed pointer is a symlink the rootfs builder writes at
        # /aos-toplevel -> /nix/store/<hash>-toplevel. readlink
        # returns the literal target (a /nix/store/... path); we
        # access toplevel-resident files by prefixing /sysroot
        # because the real root is still under /sysroot in the
        # initrd. /sysroot/nix is the merged overlay (set up by
        # nix-overlay-setup.service, which we ordered After).
        toplevel=$(readlink /sysroot/aos-toplevel)

        read_meta() {
          tr -d '\n' < "/sysroot$toplevel/meta/$1" 2>/dev/null \
            || printf 'unknown'
        }

        fail_image_identity() {
          echo "aos-seed-profiles: $*" >&2
          exit 1
        }

        read_os_release() {
          wanted=$1
          source=$2
          found=0
          result=
          while IFS= read -r line; do
            case "$line" in
              "$wanted="*)
                found=$((found + 1))
                result=''${line#*=}
                result=''${result#\"}
                result=''${result%\"}
                ;;
            esac
          done < "$source"
          [ "$found" -eq 1 ] || return 1
          printf '%s' "$result"
        }

        read_cmdline_value() {
          wanted=$1
          found=0
          result=
          for word in $(cat /proc/cmdline); do
            case "$word" in
              "$wanted="*)
                found=$((found + 1))
                result=''${word#*=}
                ;;
            esac
          done
          [ "$found" -le 1 ] || return 1
          printf '%s' "$result"
        }

        read_pcr11() {
          # cryptsetup may leave the swtpm resource manager busy briefly after
          # an unattended unlock. Never let an informational PCR read wedge
          # switch-root indefinitely.
          output=$(${pkgs.coreutils}/bin/timeout -k 5 15 \
            tpm2_pcrread sha256:11 2>/dev/null) || return 1
          for word in $output; do
            case "$word" in
              0x*)
                value=''${word#0x}
                [ "''${#value}" -eq 64 ] || continue
                printf '%s' "$value" | tr '[:upper:]' '[:lower:]'
                return 0
                ;;
            esac
          done
          return 1
        }

        abi=$(read_meta module-abi)
        baselib_digest=$(read_meta baselib-digest)
        base_lib=$(readlink "/sysroot$toplevel/base-lib")
        uki_path=$(read_meta uki-path)
        kern=$(readlink "/sysroot$toplevel/kernel" 2>/dev/null || true)
        [ -n "$kern" ] || kern="$toplevel/kernel"
        now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

        case "$toplevel" in
          /nix/store/*) ;;
          *) fail_image_identity "immutable toplevel has unsafe target $toplevel" ;;
        esac
        case "$base_lib" in
          /nix/store/*) ;;
          *) fail_image_identity "immutable base-lib has unsafe target $base_lib" ;;
        esac
        case "$uki_path" in
          EFI/Linux/*.efi) ;;
          *) fail_image_identity "immutable image records unsafe UKI path $uki_path" ;;
        esac
        os_release=$(readlink "/sysroot$toplevel/os-release") \
          || fail_image_identity "immutable toplevel has no os-release"
        case "$os_release" in
          /nix/store/*) ;;
          *) fail_image_identity "immutable os-release has unsafe target $os_release" ;;
        esac
        os_abi=$(read_os_release AOS_MODULE_ABI "/sysroot$os_release") \
          || fail_image_identity "immutable os-release has no unique module ABI"
        os_digest=$(read_os_release AOS_BASELIB_DIGEST "/sysroot$os_release") \
          || fail_image_identity "immutable os-release has no unique base-lib digest"
        os_version=$(read_os_release VERSION_ID "/sysroot$os_release") \
          || fail_image_identity "immutable os-release has no unique version"
        [ "$abi" = "$os_abi" ] \
          || fail_image_identity "toplevel metadata disagrees with measured module ABI"
        [ "$baselib_digest" = "$os_digest" ] \
          || fail_image_identity "toplevel metadata disagrees with measured base-lib digest"
        [ "$(read_meta version)" = "$os_version" ] \
          || fail_image_identity "toplevel metadata disagrees with measured version"

        root_hash=$(read_cmdline_value roothash) \
          || fail_image_identity "kernel command line has ambiguous roothash"
        root_device=$(read_cmdline_value root) \
          || fail_image_identity "kernel command line has ambiguous root device"
        verity_data=$(read_cmdline_value systemd.verity_root_data) \
          || fail_image_identity "kernel command line has ambiguous verity data device"
        slot_device=$verity_data
        [ -n "$slot_device" ] || slot_device=$root_device
        case "$slot_device" in
          /dev/disk/by-partlabel/root-a) boot_slot=A ;;
          /dev/disk/by-partlabel/root-b) boot_slot=B ;;
          *)
            slot_real=$(readlink -f "$slot_device" 2>/dev/null || true)
            root_a_real=$(readlink -f /dev/disk/by-partlabel/root-a 2>/dev/null || true)
            root_b_real=$(readlink -f /dev/disk/by-partlabel/root-b 2>/dev/null || true)
            if [ -n "$slot_real" ] && [ "$slot_real" = "$root_a_real" ]; then
              boot_slot=A
            elif [ -n "$slot_real" ] && [ "$slot_real" = "$root_b_real" ]; then
              boot_slot=B
            else
              fail_image_identity "kernel command line does not identify root-a or root-b"
            fi
            ;;
        esac
        # `/aos-toplevel` is baked into the booted immutable root. Reconcile
        # the userspace image index to that identity before stage 2; the
        # currently selected config generation is never used as authority.
        mkdir -p "$image_dir"
        publish_image_state() {
          source=$1
          ${pkgs.coreutils}/bin/sync -f "$source"
          mv "$source" "$image_dir/state.json"
          ${pkgs.coreutils}/bin/sync -f "$image_dir"
        }

        existing=0
        if [ -e "$image_dir/state.json" ]; then
          existing=$(${pkgs.jq}/bin/jq --arg top "$toplevel" \
            '[.generations[] | select(.toplevel == $top) | .number][0] // 0' \
            "$image_dir/state.json")
        fi
        initrd_pcr11=
        steady_recurrent=false
        if [ "$existing" -eq 0 ]; then
          # Indexing a genuinely new immutable image requires a live reading.
          # An unavailable TPM preserves the historical unmeasured-record
          # representation rather than inventing an expected PCR value.
          if measured=$(read_pcr11); then
            initrd_pcr11=$measured
          fi
        else
          # On a recurrent boot, /var has just been unsealed and the immutable
          # image record is checked field-by-field below. Reuse its indexed
          # expectation here instead of contending with cryptsetup for the TPM;
          # stage 2 independently quotes the live PCR bank for attestation.
          initrd_pcr11=$(${pkgs.jq}/bin/jq -er --argjson existing "$existing" \
            '[.generations[] | select(.number == $existing) | .initrd_pcr11][0] // ""' \
            "$image_dir/state.json")
          if [ -z "$initrd_pcr11" ]; then
            if measured=$(read_pcr11); then
              initrd_pcr11=$measured
            fi
          fi
          case "$initrd_pcr11" in
            "") ;;
            *[!0-9A-Fa-f]*)
              fail_image_identity "persisted image record has malformed initrd PCR 11"
              ;;
            *)
              [ "''${#initrd_pcr11}" -eq 64 ] \
                || fail_image_identity "persisted image record has malformed initrd PCR 11"
              ;;
          esac
          initrd_pcr11=$(printf '%s' "$initrd_pcr11" | tr '[:upper:]' '[:lower:]')
        fi

        if [ ! -e "$image_dir/state.json" ]; then
          ${pkgs.jq}/bin/jq -n \
            --arg pn "$(read_meta package-name)" \
            --arg ver "$(read_meta version)" \
            --arg top "$toplevel" \
            --arg kern "$kern" \
            --arg base "$base_lib" \
            --arg digest "$baselib_digest" \
            --arg now "$now" \
            --arg uki "$uki_path" \
            --arg slot "$boot_slot" \
            --arg root_hash "$root_hash" \
            --arg initrd_pcr11 "$initrd_pcr11" \
            --argjson abi "$abi" \
            '{ running: 1, default: 1, pending: 1,
               generations: [({ number: 1, slot: $slot, uki_path: $uki,
                 toplevel: $top, package_name: $pn, version: $ver,
                 registry: "seed", kernel_path: $kern,
                 evaluator_ref: $base, module_abi: $abi,
                 baselib_digest: $digest, created_at: $now }
                 + (if $root_hash == "" then {} else {root_verity_roothash: $root_hash} end)
                 + (if $initrd_pcr11 == "" then {} else {initrd_pcr11: $initrd_pcr11} end))] }' \
            > "$image_dir/.state.json.new"
          publish_image_state "$image_dir/.state.json.new"
          existing=1
        else
          if [ "$existing" -eq 0 ]; then
            next=$(${pkgs.jq}/bin/jq '[.generations[].number] | max + 1' "$image_dir/state.json")
            ${pkgs.jq}/bin/jq \
              --arg pn "$(read_meta package-name)" --arg ver "$(read_meta version)" \
              --arg top "$toplevel" --arg kern "$kern" --arg base "$base_lib" \
              --arg digest "$baselib_digest" --arg now "$now" \
              --arg uki "$uki_path" --arg slot "$boot_slot" \
              --arg root_hash "$root_hash" --arg initrd_pcr11 "$initrd_pcr11" \
              --argjson abi "$abi" --argjson next "$next" \
              '.generations += [({ number: $next,
                 slot: $slot,
                 uki_path: $uki, toplevel: $top, package_name: $pn,
                 version: $ver, registry: "seed", kernel_path: $kern,
                 evaluator_ref: $base, module_abi: $abi,
                 baselib_digest: $digest, created_at: $now }
                 + (if $root_hash == "" then {} else {root_verity_roothash: $root_hash} end)
                 + (if $initrd_pcr11 == "" then {} else {initrd_pcr11: $initrd_pcr11} end))]
               | .running = $next' \
              "$image_dir/state.json" > "$image_dir/.state.json.new"
            publish_image_state "$image_dir/.state.json.new"
            existing=$next
          else
            top_count=$(${pkgs.jq}/bin/jq --arg top "$toplevel" \
              '[.generations[] | select(.toplevel == $top)] | length' \
              "$image_dir/state.json")
            matching=$(${pkgs.jq}/bin/jq \
              --arg top "$toplevel" --arg pn "$(read_meta package-name)" \
              --arg ver "$(read_meta version)" --arg kern "$kern" \
              --arg base "$base_lib" --arg digest "$baselib_digest" \
              --arg uki "$uki_path" --arg slot "$boot_slot" \
              --arg root_hash "$root_hash" --arg initrd_pcr11 "$initrd_pcr11" \
              --argjson abi "$abi" \
              '[.generations[] | select(
                 .toplevel == $top and .package_name == $pn and .version == $ver
                 and .kernel_path == $kern and .evaluator_ref == $base
                 and .module_abi == $abi and .baselib_digest == $digest
                 and .uki_path == $uki and .slot == $slot
                 and ((.root_verity_roothash // "") == $root_hash)
                 and ((.initrd_pcr11 == null)
                      or (.initrd_pcr11 != null and $initrd_pcr11 != ""
                          and (.initrd_pcr11 | ascii_downcase) == $initrd_pcr11))
               )] | length' "$image_dir/state.json")
            [ "$top_count" -eq 1 ] && [ "$matching" -eq 1 ] \
              || fail_image_identity "persisted image record disagrees with the booted immutable image"
            recorded_running=$(${pkgs.jq}/bin/jq -er '.running' \
              "$image_dir/state.json")
            recorded_initrd=$(${pkgs.jq}/bin/jq -r --argjson existing "$existing" \
              '[.generations[] | select(.number == $existing) | .initrd_pcr11][0] // ""' \
              "$image_dir/state.json")
            if [ -z "$recorded_initrd" ] && [ -n "$initrd_pcr11" ]; then
              # Preserve the catalog-published stable PCR 11 separately. For
              # legacy seed records only, an equal old expected value was the
              # initrd snapshot and is migrated rather than reinterpreted as
              # the stable ready-phase value.
              ${pkgs.jq}/bin/jq \
                --argjson existing "$existing" --arg initrd "$initrd_pcr11" \
                '.running = $existing
                 | (.generations[] | select(.number == $existing)) |=
                   (.initrd_pcr11 = $initrd
                    | if .registry == "seed"
                         and ((.expected_pcr11 // "") | ascii_downcase) == $initrd
                      then del(.expected_pcr11)
                      else .
                      end)' \
                "$image_dir/state.json" > "$image_dir/.state.json.new"
              publish_image_state "$image_dir/.state.json.new"
            elif [ "$recorded_running" -ne "$existing" ]; then
              ${pkgs.jq}/bin/jq --argjson running "$existing" \
                '.running = $running' \
                "$image_dir/state.json" > "$image_dir/.state.json.new"
              publish_image_state "$image_dir/.state.json.new"
            else
              steady_recurrent=true
            fi
          fi
        fi

        # A fully reconciled recurrent boot is read-only. Avoid refreshing
        # durable roots and copying state immediately after TPM-unlocking
        # /var; those mutations are repair operations, not boot requirements.
        # Any missing root or legacy state falls through to the repair path.
        if [ "$steady_recurrent" = true ]; then
          retained_base=$(readlink \
            "$image_dir/image-gen-$existing/baselib/$abi" 2>/dev/null || true)
          if [ "$retained_base" = "$base_lib" ] && [ -e "$profile_dir/state.json" ]; then
            has_legacy=$(${pkgs.jq}/bin/jq \
              '[.generations[] | has("toplevel")] | any' \
              "$profile_dir/state.json")
            if [ "$has_legacy" = false ]; then
              link=$(readlink "$profile_dir/current" 2>/dev/null || true)
              GEN=''${link#gen-}
              [ -n "$GEN" ] || GEN=0
              printf 'AOS_PROFILE_GEN=%s\n' "$GEN" > /run/aos-profile-gen.env
              exit 0
            fi
          fi
        fi

        mkdir -p "$image_dir/image-gen-$existing/baselib"
        ln -sfn "$base_lib" "$image_dir/image-gen-$existing/baselib/$abi"
        mkdir -p "$profile_dir"

        # One-shot legacy migration. Every bundled record must both carry the
        # complete config-generation input/output binding and authenticate its
        # retired toplevel fields through mutually agreeing immutable metadata,
        # os-release, base-lib, and image-index fields. Migration is all-or-
        # nothing; incomplete records leave the original state untouched.
        if [ -e "$profile_dir/state.json" ]; then
          cp "$profile_dir/state.json" "$profile_dir/.state.json.migrate"
          has_legacy=$(${pkgs.jq}/bin/jq '[.generations[] | has("toplevel")] | any' \
            "$profile_dir/.state.json.migrate")
          migration_failed=0
          for index in $(${pkgs.jq}/bin/jq -r \
            '.generations | to_entries[] | select(.value | has("toplevel")) | .key' \
            "$profile_dir/.state.json.migrate"); do
            legacy_top=$(${pkgs.jq}/bin/jq -r --argjson index "$index" \
              '.generations[$index].toplevel' "$profile_dir/.state.json.migrate")
            case "$legacy_top" in
              /nix/store/*) ;;
              *)
                echo "aos-seed-profiles: legacy generation $index has unsafe toplevel" >&2
                migration_failed=1
                continue
                ;;
            esac
            legacy_abi=$(tr -d '\n' < "/sysroot$legacy_top/meta/module-abi" 2>/dev/null || true)
            legacy_digest=$(tr -d '\n' < "/sysroot$legacy_top/meta/baselib-digest" 2>/dev/null || true)
            legacy_base=$(readlink "/sysroot$legacy_top/base-lib" 2>/dev/null || true)
            legacy_osrel=$(readlink "/sysroot$legacy_top/os-release" 2>/dev/null || true)
            [ -n "$legacy_abi" ] || { migration_failed=1; continue; }
            case "$legacy_abi" in *[!0-9]*) migration_failed=1; continue ;; esac
            case "$legacy_base" in /nix/store/*) ;; *) migration_failed=1; continue ;; esac
            case "$legacy_osrel" in /nix/store/*) ;; *) migration_failed=1; continue ;; esac
            legacy_os_abi=$(read_os_release AOS_MODULE_ABI "/sysroot$legacy_osrel" 2>/dev/null || true)
            legacy_os_digest=$(read_os_release AOS_BASELIB_DIGEST "/sysroot$legacy_osrel" 2>/dev/null || true)
            [ "$legacy_abi" = "$legacy_os_abi" ] || { migration_failed=1; continue; }
            [ -n "$legacy_digest" ] && [ "$legacy_digest" = "$legacy_os_digest" ] \
              || { migration_failed=1; continue; }

            legacy_matches=$(${pkgs.jq}/bin/jq \
              --arg top "$legacy_top" --arg base "$legacy_base" \
              --arg digest "$legacy_digest" --argjson abi "$legacy_abi" \
              '[.generations[] | select(.toplevel == $top
                 and .evaluator_ref == $base and .module_abi == $abi
                 and .baselib_digest == $digest)] | length' \
              "$image_dir/state.json")
            [ "$legacy_matches" -eq 1 ] || { migration_failed=1; continue; }
            legacy_parent=$(${pkgs.jq}/bin/jq -r \
              --arg top "$legacy_top" --arg base "$legacy_base" \
              --arg digest "$legacy_digest" --argjson abi "$legacy_abi" \
              '.generations[] | select(.toplevel == $top
                 and .evaluator_ref == $base and .module_abi == $abi
                 and .baselib_digest == $digest) | .number' \
              "$image_dir/state.json")
            ${pkgs.jq}/bin/jq --argjson index "$index" \
              --argjson abi "$legacy_abi" --argjson parent "$legacy_parent" \
              --arg base "$legacy_base" \
              '.generations[$index].module_abi_pinned = $abi
               | .generations[$index].image_gen_parent = $parent
               | .generations[$index].base_lib_ref = $base' \
              "$profile_dir/.state.json.migrate" > "$profile_dir/.state.json.next"
            mv "$profile_dir/.state.json.next" "$profile_dir/.state.json.migrate"
          done
          complete=$(${pkgs.jq}/bin/jq '
            all(.generations[];
              (.image_gen_parent | type) == "number"
              and (.module_abi_pinned | type) == "number"
              and (.manifest_hash | type) == "string" and (.manifest_hash | length) > 0
              and (.config_module_closure | type) == "string" and (.config_module_closure | length) > 0
              and (.config_module_paths | type) == "array"
              and (.config_module_packages | type) == "array"
              and (.host_nix_ref | type) == "string" and (.host_nix_ref | length) > 0
              and (.facts_hash | type) == "string" and (.facts_hash | length) > 0
              and (.facts_ref | type) == "string" and (.facts_ref | length) > 0
              and (.base_lib_ref | type) == "string" and (.base_lib_ref | length) > 0
              and (.evaluator_ref | type) == "string" and (.evaluator_ref | length) > 0))' \
            "$profile_dir/.state.json.migrate")
          if [ "$has_legacy" = true ] && { [ "$migration_failed" -ne 0 ] || [ "$complete" != true ]; }; then
            rm -f "$profile_dir/.state.json.migrate"
            echo "aos-seed-profiles: legacy system state cannot be authenticated as complete config generations" >&2
            exit 1
          fi
          if [ "$has_legacy" = true ]; then
            ${pkgs.jq}/bin/jq '
              .generations |= map({
                number, image_gen_parent, module_abi_pinned, manifest_hash,
                config_module_closure, config_module_paths,
                config_module_packages, host_nix_ref, host_nix_commit,
                facts_hash, facts_ref, base_lib_ref, evaluator_ref, created_at
              })' "$profile_dir/.state.json.migrate" \
              > "$profile_dir/.state.json.next"
            mv "$profile_dir/.state.json.next" "$profile_dir/.state.json.migrate"
            ${pkgs.coreutils}/bin/sync -f "$profile_dir/.state.json.migrate"
            mv "$profile_dir/.state.json.migrate" "$profile_dir/state.json"
            ${pkgs.coreutils}/bin/sync -f "$profile_dir"
          else
            rm -f "$profile_dir/.state.json.migrate"
          fi
        fi

        if [ ! -e "$profile_dir/state.json" ]; then
          # A baked image is an image-generation, not an empty synthetic
          # config-generation. The first successful on-host evaluation creates
          # config-gen 1 with all authenticated input/output bindings present.
          ${pkgs.jq}/bin/jq -n \
            '{current: 0, next: 1, generations: []}' \
            > "$profile_dir/.state.json.new"
          ${pkgs.coreutils}/bin/sync -f "$profile_dir/.state.json.new"
          mv "$profile_dir/.state.json.new" "$profile_dir/state.json"
          ${pkgs.coreutils}/bin/sync -f "$profile_dir"
        fi

        link=$(readlink "$profile_dir/current" 2>/dev/null || true)
        GEN=''${link#gen-}
        [ -n "$GEN" ] || GEN=0
        printf 'AOS_PROFILE_GEN=%s\n' "$GEN" > /run/aos-profile-gen.env
      '';
    };

    # Mount a tmpfs on /run/etc once, before anything else writes
    # under it. The files backend writes its per-gen
    # /run/etc/config-<gen>/ subtree here, and etc-overlay-setup
    # later creates the system-<gen> mount points and the upper-<gen>
    # dir (a plain directory, not its own mount) alongside.
    #
    # Why the initrd's /run rather than /sysroot/run:
    # systemd-initrd-switch-root does `mount --move /run
    # /sysroot/run` (then pivots) when handing off to stage-2. The
    # move carries the initrd's /run mount and any sub-mounts of
    # it; a separate mount on /sysroot/run/etc would be parented
    # to the sysroot fs, end up as a sibling of the moved /run
    # mount post-pivot, and be shadowed (path traversal goes
    # through the moved /run's empty /etc directory). Mounting
    # /run/etc here makes it a true child of the initrd's /run,
    # so the move carries it and its sub-mounts (the system EROFS,
    # the content bind, the per-gen files lower, the tmpfs
    # upper) into stage-2 still reachable at /run/etc/... by path.
    "run-etc-setup" = {
      description = "Mount /run/etc tmpfs";
      wantedBy = ["initrd-fs.target"];
      before = [
        filesUnit
        "etc-overlay-setup.service"
        "initrd-fs.target"
      ];
      unitConfig = {
        DefaultDependencies = "no";
        ConditionPathIsMountPoint = "!/run/etc";
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p /run/etc";
        ExecStart =
          "${pkgs.util-linux}/bin/mount -t tmpfs -o nosuid,nodev,mode=755 "
          + "tmpfs /run/etc";
      };
    };

    # Seed /var/etc/machine-id on first boot, before
    # etc-overlay-setup mounts the overlay (so stage-2
    # systemd-machine-id-setup.service sees the file via the
    # /var/etc lower and skips regeneration). Stage-1 placement avoids the race where stage-2's
    # systemd-machine-id-setup writes to the tmpfs upperdir,
    # regenerating the ID every reboot. Spec v12 §6.1.5.
    "aos-machine-id" = {
      description = "Seed /var/etc/machine-id on first boot";
      wantedBy = ["initrd-fs.target"];
      before = [
        "etc-overlay-setup.service"
        "initrd-fs.target"
      ];
      requires = [
        "sysroot.mount"
        "mount-var.service"
      ];
      after = [
        "sysroot.mount"
        "mount-var.service"
      ];
      unitConfig = {
        DefaultDependencies = "no";
        ConditionPathExists = "!/sysroot/var/etc/machine-id";
      };
      environment.PATH = bootPath;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        set -euo pipefail
        mkdir -p /sysroot/var/etc
        # /proc/sys/kernel/random/uuid emits
        # "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\n". systemd's
        # machine-id format is 32 lowercase hex chars (no dashes)
        # followed by a newline; tr removes the dashes, the
        # trailing newline from /proc survives.
        tr -d '-' < /proc/sys/kernel/random/uuid \
          > /sysroot/var/etc/machine-id
        chmod 0444 /sysroot/var/etc/machine-id
      '';
    };
  };
in {
  config = {
    # Initrd services. The cpio assembler in modules/base/initrd-builder.nix
    # picks these up via `system.build.systemdInitrdUnits`.
    boot.initrd.systemd.services = neutralBootServices;

    # DHCP on every physical NIC in the initrd. IPv4 link-local addressing is
    # the DHCP-less metadata bootstrap: it provides an on-link source address
    # and route to 169.254.169.254 so the agent can learn the provider's real
    # static address. Kind=!* excludes virtual links (bridges/bonds/etc.).
    # Brought up only when the network gate fires (cloud platforms).
    boot.initrd.systemd.network."80-dhcp" = {
      matchConfig = {
        Type = "ether";
        Kind = "!*";
      };
      networkConfig = {
        DHCP = "yes";
        LinkLocalAddressing = "ipv4";
        IPv4LLRoute = true;
      };
    };
  };
}
