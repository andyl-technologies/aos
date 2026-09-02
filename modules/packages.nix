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
  packageMetaFile = name: package: let
    packageHash = storePathHash package.package;
    packageVersion = package.package.version or "0";
    configOutput =
      if package.package ? config
      then builtins.toString package.package.config
      else "";
  in
    pkgs.runCommand "aos-package-${name}-meta.json" {
      buildDeps = [pkgs.coreutils pkgs.jq];
      preferLocalBuild = true;
      allowSubstitutes = false;
    } ''
      set -eu
      mkdir -p "$out"
      manifest=${package.package.expose}/manifest.json
      package_store_path=${lib.escapeShellArg (builtins.toString package.package)}
      package_name=${lib.escapeShellArg name}
      package_version=${lib.escapeShellArg packageVersion}
      config_output=${lib.escapeShellArg configOutput}
      if [ -n "$config_output" ]; then
        config_meta="$config_output/config-meta.json"
      else
        config_meta=/dev/null
      fi
      jq -n \
        --slurpfile manifest "$manifest" \
        --arg store_path "$package_store_path" \
        --arg name "$package_name" \
        --arg version "$package_version" \
        --arg expose_path ${lib.escapeShellArg (builtins.toString package.package.expose)} \
        -e '(($manifest[0].expose | type) == "object") and (($manifest[0].permissions | type) == "object")' >/dev/null

      root_hash=$(jq -r '[.expose.images[]? | select((.root_hash // "") != "" and (.root_hash_sig // "") != "")][0].root_hash // ""' "$manifest")
      root_hash_sig=$(jq -r '[.expose.images[]? | select((.root_hash // "") != "" and (.root_hash_sig // "") != "")][0].root_hash_sig // ""' "$manifest")
      if [ -n "$root_hash" ]; then
        case "$root_hash" in
          sha256:*) root_digest="$root_hash" ;;
          sha256-*) root_digest="sha256:''${root_hash#sha256-}" ;;
          *) root_digest="$root_hash" ;;
        esac
        root_digest=$(printf '%s' "$root_digest" | tr 'A-F' 'a-f')
      else
        root_digest="sha256:$(printf '%s' "$package_store_path" | sha256sum | cut -d ' ' -f 1)"
      fi
      manifest_digest="sha256:$(sha256sum "$manifest" | cut -d ' ' -f 1)"
      word="aos-package-v1|name=''${#package_name}:$package_name|version=''${#package_version}:$package_version|root-digest=''${#root_digest}:$root_digest|manifest-digest=''${#manifest_digest}:$manifest_digest"
      measurement="sha256:$(printf '%s' "$word" | sha256sum | cut -d ' ' -f 1)"

      jq -n \
        --slurpfile manifest "$manifest" \
        --arg store_path "$package_store_path" \
        --arg name "$package_name" \
        --arg version "$package_version" \
        --arg expose_path ${lib.escapeShellArg (builtins.toString package.package.expose)} \
        --arg config_output "$config_output" \
        --slurpfile config_meta "$config_meta" \
        --arg root_hash "$root_hash" \
        --arg root_hash_sig "$root_hash_sig" \
        --arg root_digest "$root_digest" \
        --arg measurement "$measurement" \
        '{
          store_path: $store_path,
          pushed_at: 1,
          pushed_by: "aos-image",
          expires_at: null,
          is_root: true,
          last_accessed: 1,
          access_count: 0,
          apm: {
            name: $name,
            version: $version,
            explicit: true,
            registry: "seed",
            installed_at: "1970-01-01T00:00:00Z",
            held: false,
            source_drv: "",
            source_nar_hash: "",
            expose: $manifest[0].expose,
            expose_artifact: {
              store_path: $expose_path,
              nar_hash: "sha256:aos-image",
              nar_size: 1
            },
            config_module: (
              if $config_output == "" then null
              else {
                config_output: {
                  store_path: $config_output,
                  nar_hash: "sha256:aos-image",
                  nar_size: 1,
                  references: []
                },
                evaluation_base_lib: null,
                module_abi_compat: $config_meta[0].module_abi_compat,
                declares: $config_meta[0].declares,
                declaration_schema: [],
                requires: [],
                owns_roots: $config_meta[0].owns_roots,
                contributes: $config_meta[0].contributes,
                provides_capabilities: $config_meta[0].provides_capabilities,
                artifacts: ($config_meta[0].artifacts // {})
              }
              end
            ),
            permissions: $manifest[0].permissions,
            attestation: ({
              root_digest: $root_digest,
              measurement: $measurement
            } + (
              if $root_hash == "" then {}
              else {
                root_hash: $root_hash,
                root_hash_sig: $root_hash_sig
              }
              end
            ))
          }
        }' > "$out/${packageHash}.json"

      jq -n \
        --arg name "$package_name" \
        --arg version "$package_version" \
        --arg root_digest "$root_digest" \
        --arg measurement "$measurement" \
        '{
          name: $name,
          version: $version,
          root_digest: $root_digest,
          measurement: $measurement
        }' > "$out/${packageHash}.attestation.json"
    '';

  # The package-profile seed is an image-fixed artifact (a
  # function of the bundled packages, not host.nix). Reference the resolved
  # `artifacts.aos-package-profile-seed` (frozen store path on the on-host
  # evaluator, the live derivation below otherwise — byte-identical).
  packageSeedBundle = config.aos.config.artifacts.aos-package-profile-seed;
  packageSeedBundleDrv =
    pkgs.runCommand "aos-package-profile-seed" {
      buildDeps = [pkgs.coreutils];
      preferLocalBuild = true;
      allowSubstitutes = false;
    } ''
      set -eu
      mkdir -p "$out/gen-1/usr" "$out/gen-1/expose" "$out/gen-1/cfgsrc" "$out/gen-1/meta" "$out/meta"
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
            configLink = lib.optionalString (package.package ? config) ''
              ln -sfn ${package.package.config} "$out/gen-1/cfgsrc/${storePathHash package.package.config}"
            '';
          in ''
            ln -sfn ${package.package} "$out/gen-1/usr/${packageHash}"
            ln -sfn ${package.package.expose} "$out/gen-1/expose/${exposeHash}"
            ${configLink}
            cp ${metaFile}/${packageHash}.json "$out/meta/${packageHash}.json"
            cp ${metaFile}/${packageHash}.json "$out/gen-1/meta/${packageHash}.json"
          ''
        )
        exposedBundledPackages
      )}
    '';

  packageAttestationCatalog = let
    metaFiles =
      lib.mapAttrsToList (
        name: package: let
          packageHash = storePathHash package.package;
          metaFile = packageMetaFile name package;
        in "${metaFile}/${packageHash}.attestation.json"
      )
      exposedBundledPackages;
  in
    pkgs.runCommand "aos-package-attestation-catalog.json" {
      buildDeps = [pkgs.jq];
      preferLocalBuild = true;
      allowSubstitutes = false;
    } ''
      set -eu
      mkdir -p "$out"
      ${
        if metaFiles == []
        then ''
          printf '[]\n' > "$out/package-attestation-catalog.json"
        ''
        else ''
          jq -s '.' ${lib.escapeShellArgs metaFiles} > "$out/package-attestation-catalog.json"
        ''
      }
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
          configLink = lib.optionalString (package.package ? config) ''
            ${pkgs.coreutils}/bin/ln -sfn ${package.package.config} "$profile/gen-1/cfgsrc/${storePathHash package.package.config}"
          '';
        in ''
          ${name})
            ${pkgs.coreutils}/bin/ln -sfn ${package.package} "$profile/gen-1/usr/${packageHash}"
            ${pkgs.coreutils}/bin/ln -sfn ${package.package.expose} "$profile/gen-1/expose/${exposeHash}"
            ${configLink}
            ${pkgs.coreutils}/bin/cp ${metaFile}/${packageHash}.json "$profile/meta/${packageHash}.json"
            ${pkgs.coreutils}/bin/cp ${metaFile}/${packageHash}.json "$profile/gen-1/meta/${packageHash}.json"
            ;;
        ''
      )
      exposedBundledPackages);

  reconcileExposedUnits = pkgs.writeShellScriptBin "aos-reconcile-exposed-units" ''
    exec ${pkgs.aos.packageRuntime}/bin/aos-package-runtime _test-reconcile-exposed-units "$@"
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
    # Register the package-profile seed as an image-fixed config artifact
    # Guarded on frozenArtifacts so the on-host frozen pkgs
    # (no `runCommand`) never evaluates the source.
    aos.config._artifactSources.aos-package-profile-seed =
      if config.aos.config.frozenArtifacts ? "aos-package-profile-seed"
      then null
      else packageSeedBundleDrv;

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
          _: package:
            [
              package.package
              package.package.expose
            ]
            ++ lib.optional (package.package ? config) package.package.config
        )
        exposedBundledPackages);

    environment.etc."aos/package-attestation-catalog.json" = lib.mkIf (exposedBundledPackages != {}) {
      source = "${packageAttestationCatalog}/package-attestation-catalog.json";
    };

    systemd.services.aos-seed-baked-packages = lib.mkIf (exposedBundledPackages != {}) {
      description = "Seed baked AOS package profile";
      wantedBy = ["multi-user.target"];
      before = [
        "aos-install-baked-packages.service"
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
            ${pkgs.coreutils}/bin/mkdir -p "$profile/gen-1/usr" "$profile/gen-1/expose" "$profile/gen-1/cfgsrc" "$profile/gen-1/meta" "$profile/meta"
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
        AOS_EXPOSE_START_NO_WAIT=1 ${reconcileExposedUnits}/bin/aos-reconcile-exposed-units --system
      '';
    };
  };
}
