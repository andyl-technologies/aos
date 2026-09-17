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

  initrdAbilityGraph = config.system.build.initrdAbilityGraph;
  handoffInterface = lib.abilities.interfaces.bootPreparation.interfaces.handoff;
  abilityTypes = lib.abilities.types;
  handoffResourceType = abilityTypes.record {
    fields = {
      resource = abilityTypes.resourceId;
      kind = abilityTypes.qualifiedName;
      lifetime = abilityTypes.lifetime;
      value = handoffInterface.requestType;
      controller = abilityTypes.declarationKey;
      realization = handoffInterface.realizationType;
    };
  };
  handoffSelectionType = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.boot.preparation-handoff-selection/v1"];
      binding = abilityTypes.record {
        fields = {
          name = abilityTypes.declarationKey;
          request = abilityTypes.declarationKey;
          implementation = abilityTypes.declarationKey;
          providerInstance = abilityTypes.declarationKey;
          slot = abilityTypes.localKey;
        };
      };
      resource = handoffResourceType;
    };
  };
  handoffResources =
    if initrdAbilityGraph == null
    then []
    else
      builtins.filter
      (resource: resource.kind == handoffInterface.name)
      (builtins.attrValues initrdAbilityGraph.resolvedResources);
  bootPreparationHandoff =
    if !config.aos.boot.initrd.abilityHandoff.enable
    then null
    else if initrdAbilityGraph == null
    then throw "boot preparation handoff requires the final initrd ability fixed point"
    else if builtins.length handoffResources != 1
    then throw "boot preparation handoff must resolve exactly one selected resource"
    else let
      resource = builtins.head handoffResources;
      binding = initrdAbilityGraph.bindings.${resource.controller};
    in {
      schema = "aos.boot.preparation-handoff-selection/v1";
      binding = {
        name = resource.controller;
        inherit
          (binding)
          request
          implementation
          providerInstance
          slot
          ;
      };
      inherit resource;
    };
in {
  options.aos.boot.preparationHandoff = lib.mkOption {
    type = lib.types.nullOr handoffSelectionType;
    readOnly = true;
    internal = true;
    description = ''
      Exact selected initrd handoff binding and resource derived from the final
      ability fixed point. The selected manager consumes its own realization.
    '';
  };

  config = {
    aos.boot.preparationHandoff = bootPreparationHandoff;
    system.build.checks.native-executor-path = nativeExecutorPathCheck;
    system.build.checks.rooted-executable-path = rootedExecutablePathCheck;

    environment.systemPackages = [pkgs.aos-boot-preparations];
    aos.boot.initrd.packageRoots = [pkgs.aos-boot-preparations];
    aos.boot.substrateServices.handoffEnabled = config.aos.boot.initrd.abilityHandoff.enable;
    aos.abilities.stages.initrd = {
      modules = [
        {
          aos.boot.substrateServices = {
            enable = true;
            handoffEnabled = config.aos.boot.initrd.abilityHandoff.enable;
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
