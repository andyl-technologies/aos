##! modules/services/boot-substrate.nix — Neutral first-boot substrate
##!
##! Selects the package-owned, provisioning-backend-agnostic initrd services
##! that assemble the running system on first boot.
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
##! Their typed declarations order against persistent-state and configuration
##! readiness resources in the initrd ability fixed point.
{
  config,
  pkgs,
  lib,
  ...
}: let
  validateNixStoreRootShell = ''
    validate_nix_store_root() {
      value=$1
      case "$value" in
        /nix/store/*) name=''${value#/nix/store/} ;;
        *) return 1 ;;
      esac
      case "$name" in
        ""|*/*) return 1 ;;
      esac
      hash=''${name%%-*}
      store_name=''${name#*-}
      [ "$hash" != "$name" ] && [ -n "$store_name" ] || return 1
      [ "''${#hash}" -eq 32 ] || return 1
      case "$hash" in
        *[!0123456789abcdfghijklmnpqrsvwxyz]*) return 1 ;;
      esac
      case "$store_name" in
        *[!A-Za-z0-9+._?=-]*) return 1 ;;
      esac
    }
  '';
  validateRootedExecutableShell = ''
    validate_rooted_executable() {
      root=$1
      command_path=$2
      target=$(readlink "$root$command_path") || return 1

      case "$target" in
        /nix/store/*/*) ;;
        *) return 1 ;;
      esac
      store_relative=''${target#/nix/store/}
      store_entry=''${store_relative%%/*}
      executable_relative=''${store_relative#*/}
      validate_nix_store_root "/nix/store/$store_entry" || return 1
      case "/$executable_relative/" in
        *"//"*|*"/./"*|*"/../"*) return 1 ;;
      esac

      rooted_target="$root/nix/store/$store_entry/$executable_relative"
      [ ! -L "$rooted_target" ] \
        && [ -f "$rooted_target" ] \
        && [ -x "$rooted_target" ]
    }
  '';
  nativeExecutorPathCheck = pkgs.runCommand "aos-native-executor-path-check" {} ''
    ${validateNixStoreRootShell}
    valid=/nix/store/44444444444444444444444444444444-aos-package-runtime
    validate_nix_store_root "$valid"
    for invalid in \
      "$valid/bin/aos-package-runtime" \
      /nix/store/short-runtime \
      /nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-runtime \
      /tmp/44444444444444444444444444444444-runtime
    do
      if validate_nix_store_root "$invalid"; then
        echo "unexpectedly accepted native executor path: $invalid" >&2
        exit 1
      fi
    done
    touch $out
  '';
  rootedExecutablePathCheck = pkgs.runCommand "aos-rooted-executable-path-check" {} ''
    ${validateNixStoreRootShell}
    ${validateRootedExecutableShell}

    sysroot=$TMPDIR/sysroot
    store_name=44444444444444444444444444444444-rollout-tools
    rooted_store="$sysroot/nix/store/$store_name"
    mkdir -p "$sysroot/usr/bin" "$rooted_store/bin"
    printf '%s\n' '#!${pkgs.bash}/bin/bash' 'exit 0' > "$rooted_store/bin/bootctl"
    chmod 0555 "$rooted_store/bin/bootctl"
    ln -s "/nix/store/$store_name/bin/bootctl" "$sysroot/usr/bin/bootctl"

    # An initrd lookup follows the absolute link in its own namespace. The
    # validator must instead inspect the executable below the mounted root.
    test ! -x "$sysroot/usr/bin/bootctl"
    validate_rooted_executable "$sysroot" /usr/bin/bootctl

    chmod 0444 "$rooted_store/bin/bootctl"
    if validate_rooted_executable "$sysroot" /usr/bin/bootctl; then
      echo "unexpectedly accepted a non-executable command" >&2
      exit 1
    fi

    printf '%s\n' '#!${pkgs.bash}/bin/bash' 'exit 0' > "$TMPDIR/escape"
    chmod 0555 "$TMPDIR/escape"
    ln -sfn "$TMPDIR/escape" "$rooted_store/bin/bootctl"
    if validate_rooted_executable "$sysroot" /usr/bin/bootctl; then
      echo "unexpectedly accepted a store-local symlink escape" >&2
      exit 1
    fi

    ln -sfn "$TMPDIR/escape" "$sysroot/usr/bin/bootctl"
    if validate_rooted_executable "$sysroot" /usr/bin/bootctl; then
      echo "unexpectedly accepted a command outside the store" >&2
      exit 1
    fi

    touch $out
  '';

  # This is a read-only description of the package-owned handoff services.
  bootSubstrateContract = {
    completionTarget = "initrd-fs.target";
    requiredUnits =
      lib.optionals config.aos.boot.initrd.abilityHandoff.enable [
        "aos-ability-initrd-controller.service"
        "aos-ability-initrd-handoff-barrier.service"
      ]
      ++ [
        "aos-config-seed.service"
        "aos-credential-recovery.service"
        "aos-machine-id.service"
        "aos-seed-profiles.service"
        "etc-overlay-setup.service"
        "mount-var.service"
        "nix-overlay-setup.service"
        "run-etc-setup.service"
      ];
    preservedMounts = [
      {
        initrdPath = "/run";
        hostPath = "/run";
      }
      {
        initrdPath = "/sysroot/etc";
        hostPath = "/etc";
      }
      {
        initrdPath = "/sysroot/nix";
        hostPath = "/nix";
      }
      {
        initrdPath = "/sysroot/var";
        hostPath = "/var";
      }
    ];
    durableStateRoots = [
      {
        initrdPath = "/sysroot/var/lib/profiles/image";
        hostPath = "/var/lib/profiles/image";
      }
      {
        initrdPath = "/sysroot/var/lib/profiles/system";
        hostPath = "/var/lib/profiles/system";
      }
    ];
  };
in {
  options.system.build.bootSubstrateContract = lib.mkOption {
    type = lib.types.submodule {
      config._module.strict = true;
      options = {
        completionTarget = lib.mkOption {type = lib.types.str;};
        requiredUnits = lib.mkOption {type = lib.types.listOf lib.types.str;};
        preservedMounts = lib.mkOption {
          type = lib.types.listOf (lib.types.submodule {
            config._module.strict = true;
            options = {
              initrdPath = lib.mkOption {type = lib.types.str;};
              hostPath = lib.mkOption {type = lib.types.str;};
            };
          });
        };
        durableStateRoots = lib.mkOption {
          type = lib.types.listOf (lib.types.submodule {
            config._module.strict = true;
            options = {
              initrdPath = lib.mkOption {type = lib.types.str;};
              hostPath = lib.mkOption {type = lib.types.str;};
            };
          });
        };
      };
    };
    readOnly = true;
    internal = true;
    description = ''
      Exact mount and durable-state handoff already implemented by the neutral
      initrd units. The initrd assembly contract consumes this read-only value.
    '';
  };

  config = {
    system.build.bootSubstrateContract = bootSubstrateContract;
    system.build.checks.native-executor-path = nativeExecutorPathCheck;
    system.build.checks.rooted-executable-path = rootedExecutablePathCheck;

    environment.systemPackages = [pkgs.aos-boot-preparations];
    aos.boot.initrd.extraPackages = [pkgs.aos-boot-preparations];
    aos.abilities.stages.initrd = {
      packages = [pkgs.aos-boot-preparations pkgs.systemd];
      intent = [
        {
          aos.boot.substrateServices = {
            enable = true;
            verityEnabled = config.aos.security.verity.enable;
            zfsEnabled = config.aos.boot.storage.backend == "zfs-zvol";
            zfsPool = config.aos.boot.storage.zfs.poolName;
            recoveryEnabled = config.aos.boot.recovery.enable;
            recoveryAbi = config.aos.boot.recovery.abi;
            espDevice = config.aos.filesystems.espDevice;
            dbCertificate =
              if config.aos.boot.recovery.enable
              then config.aos.boot.secureBoot._effectiveDbCert
              else "/nonexistent/aos-secure-boot-db.pem";
          };
        }
      ];
    };

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
