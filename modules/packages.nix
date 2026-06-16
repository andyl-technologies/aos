##! modules/packages.nix - Image-baked package policy.
##!
##! Declares the host policy layer for RFC-0001 exposed packages: which
##! package artifacts are baked into the image, which package targets receive
##! image preset enablement, and how baked packages seed apm's system package
##! profile on first boot.
{
  config,
  lib,
  pkgs,
  ...
}: let
  packageNamePattern = "[A-Za-z0-9][A-Za-z0-9+._=-]*";

  storePathHash = path:
    builtins.elemAt (lib.splitString "-" (baseNameOf (builtins.toString path))) 0;

  packageType = lib.types.submodule ({
    name,
    config,
    ...
  }: {
    options = {
      package = lib.mkOption {
        type = lib.types.package;
        description = ''
          Exposed package derivation to bake into the image for
          `aos.packages.${name}`.
        '';
      };

      bundle = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Whether this package and its rendered expose artifact are baked into
          the image. Bundled packages remain inert unless `preset` is enabled.
        '';
      };

      preset = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Whether the image preset policy enables this package's activation
          target when the baked package profile is reconciled.
        '';
      };
    };

    config.preset = lib.mkDefault config.bundle;
  });

  bundledPackages =
    lib.filterAttrs (_: package: package.bundle) config.aos.packages;
  exposedBundledPackages =
    lib.filterAttrs (_: package: package.package ? expose) bundledPackages;
  presetExposedPackages =
    lib.filterAttrs (_: package: package.preset) exposedBundledPackages;

  packageTarget = package:
    package.package.expose.passthru.manifest.expose.target;

  packageMeta = name: package: {
    store_path = builtins.toString package.package;
    pushed_at = 1;
    pushed_by = "aos-image";
    expires_at = null;
    is_root = true;
    last_accessed = 1;
    access_count = 0;
    apm = {
      inherit name;
      version = package.package.version or "0";
      explicit = true;
      registry = "seed";
      installed_at = "1970-01-01T00:00:00Z";
      held = false;
      source_drv = "";
      source_nar_hash = "";
      expose = package.package.expose.passthru.manifest.expose;
      expose_artifact = {
        store_path = builtins.toString package.package.expose;
        nar_hash = "sha256:aos-image";
        nar_size = 1;
      };
      permissions = package.package.expose.passthru.permissions;
    };
  };

  packageMetaFile = name: package: let
    packageHash = storePathHash package.package;
  in
    pkgs.writeTextFile {
      name = "aos-package-${name}-meta.json";
      text = builtins.toJSON (packageMeta name package);
      destination = "/${packageHash}.json";
    };

  packageSeedBundle =
    pkgs.runCommand "aos-package-profile-seed" {
      buildDeps = [pkgs.coreutils];
      preferLocalBuild = true;
      allowSubstitutes = false;
    } ''
      set -eu
      mkdir -p "$out/gen-1/usr" "$out/gen-1/expose" "$out/gen-1/meta" "$out/meta"
      cat > "$out/state.json" <<'JSON'
      {"current_generation":1,"next_generation":2}
      JSON
      ln -sfn gen-1 "$out/current"
      ${lib.concatStringsSep "\n" (
        lib.mapAttrsToList (
          name: package: let
            packageHash = storePathHash package.package;
            exposeHash = storePathHash package.package.expose;
            metaFile = packageMetaFile name package;
          in ''
            ln -sfn ${package.package} "$out/gen-1/usr/${packageHash}"
            ln -sfn ${package.package.expose} "$out/gen-1/expose/${exposeHash}"
            cp ${metaFile}/${packageHash}.json "$out/meta/${packageHash}.json"
            cp ${metaFile}/${packageHash}.json "$out/gen-1/meta/${packageHash}.json"
          ''
        )
        presetExposedPackages
      )}
    '';

  enabledPresetLines =
    lib.mapAttrsToList
    (_: package: "enable ${packageTarget package}")
    presetExposedPackages;

  seedPackageCases =
    lib.concatStringsSep "\n"
    (lib.mapAttrsToList (
        name: package: let
          packageHash = storePathHash package.package;
          exposeHash = storePathHash package.package.expose;
          metaFile = packageMetaFile name package;
        in ''
          ${name})
            ${pkgs.coreutils}/bin/ln -sfn ${package.package} "$profile/gen-1/usr/${packageHash}"
            ${pkgs.coreutils}/bin/ln -sfn ${package.package.expose} "$profile/gen-1/expose/${exposeHash}"
            ${pkgs.coreutils}/bin/cp ${metaFile}/${packageHash}.json "$profile/meta/${packageHash}.json"
            ${pkgs.coreutils}/bin/cp ${metaFile}/${packageHash}.json "$profile/gen-1/meta/${packageHash}.json"
            ;;
        ''
      )
      exposedBundledPackages);

  reconcileExposedUnits = pkgs.writeShellScriptBin "aos-reconcile-exposed-units" ''
    exec ${pkgs.aos}/bin/apm _test-reconcile-exposed-units "$@"
  '';
in {
  options = {
    aos.packages = lib.mkOption {
      type = lib.types.attrsOf packageType;
      default = {};
      description = ''
        Image-baked APM packages and package-target preset policy.
      '';
    };

    systemd.systemPresetRules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = ''
        Image-level systemd preset rules emitted before the default-deny
        preset file.
      '';
    };

    system.build.aosPackageProfileSeed = lib.mkOption {
      type = lib.types.package;
      description = ''
        Derivation containing the first-boot system package-profile seed.
      '';
    };
  };

  config = {
    assertions =
      lib.concatLists
      (lib.mapAttrsToList (
          name: package:
            [
              {
                assertion = builtins.match packageNamePattern name != null;
                message = ''
                  aos.packages."${name}": package names must match
                  ${packageNamePattern}. The name is used for apm metadata and
                  preset target selection.
                '';
              }
              {
                assertion = package.package ? expose;
                message = ''
                  aos.packages."${name}" must point at a derivation with an
                  `expose` artifact.
                '';
              }
              {
                assertion = !package.preset || package.bundle;
                message = ''
                  aos.packages."${name}" sets `preset = true` without
                  `bundle = true`. Preset enablement requires the package to
                  be baked into the image.
                '';
              }
            ]
            ++ lib.optionals (package.package ? expose) [
              {
                assertion = packageTarget package == "aos-pkg-${name}.target";
                message = ''
                  aos.packages."${name}" points at package target
                  ${packageTarget package}, but the policy name requires
                  aos-pkg-${name}.target.
                '';
              }
            ]
        )
        config.aos.packages);

    system.build.aosPackageProfileSeed = packageSeedBundle;

    systemd.systemPresetRules = enabledPresetLines;

    environment.systemPackages =
      lib.concatLists
      (lib.mapAttrsToList (
          _: package: [
            package.package
            package.package.expose
          ]
        )
        exposedBundledPackages);

    systemd.services.aos-seed-baked-packages = lib.mkIf (exposedBundledPackages != {}) {
      description = "Seed baked AOS package profile";
      wantedBy = ["multi-user.target"];
      before = [
        "aos-install-packages.service"
        "aos-preset.service"
        "multi-user.target"
      ];
      after = [
        "aos-seed-profiles.service"
        "nix-overlay-setup.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        profile=/var/lib/profiles/system-packages
        if [ ! -e "$profile/state.json" ]; then
          if [ -f /etc/aos/packages.d/fleet-seed ]; then
            ${pkgs.coreutils}/bin/mkdir -p "$profile/gen-1/usr" "$profile/gen-1/expose" "$profile/gen-1/meta" "$profile/meta"
            printf '%s\n' '{"current_generation":1,"next_generation":2}' > "$profile/state.json"
            ${pkgs.coreutils}/bin/ln -sfn gen-1 "$profile/current"
            seed_one() {
              case "$1" in
          ${seedPackageCases}
                *)
                  echo "unknown bundled AOS package seed '$1'" >&2
                  exit 1
                  ;;
              esac
            }
            while IFS= read -r package || [ -n "$package" ]; do
              [ -n "$package" ] || continue
              seed_one "$package"
            done < /etc/aos/packages.d/fleet-seed
          else
            ${pkgs.coreutils}/bin/mkdir -p "$profile"
            ${pkgs.coreutils}/bin/cp -a ${packageSeedBundle}/. "$profile/"
          fi
        fi
        ${reconcileExposedUnits}/bin/aos-reconcile-exposed-units --system
      '';
    };
  };
}
