##! Configures the package-owned initrd metadata and provisioning services.
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
  keyFileContent = keys: "${lib.concatStringsSep "\n" keys}\n";
  configTrustAnchors = pkgs.runCommand "aos-provisioning-trust-anchors" {} ''
    mkdir -p $out
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList (operator: keys: "printf '%s' ${lib.escapeShellArg (keyFileContent keys)} > $out/${operator}.pub")
        configKeys)}
  '';
  trustedConfigKeys =
    lib.mapAttrsToList (operator: keys: let
      content = keyFileContent keys;
    in {
      kind = "immutable-file";
      path = "${configTrustAnchors}/${operator}.pub";
      content_sha256 = "sha256:${builtins.hashString "sha256" content}";
    })
    configKeys;
  authorizationConfiguration = {
    schema = "aos.metadata.provisioning-authorization-configuration/v1";
    trust_mode = trust;
    trusted_config_keys = trustedConfigKeys;
    base_library = {
      store_path = toString config.aos.config.evalAtBoot.baseLib;
      abi_hash = config.aos.config.evalAtBoot.baseLibAbiHash;
    };
  };
in {
  options.aos.provisioning.metadataAgent.stashDir = lib.mkOption {
    type = lib.types.str;
    default = "/run/aos-metadata";
    internal = true;
    readOnly = true;
    description = ''
      Initrd metadata runtime directory. It remains below `/run` so switch-root
      carries authorized provisioning input into the host stage.
    '';
  };

  config = {
    aos.metadata.storageProvisioning.authorizationConfiguration = authorizationConfiguration;

    aos.boot.initrd.extraPackages = [
      configTrustAnchors
      config.aos.config.evalAtBoot.baseLib
      pkgs.aos.metadataRuntime
      pkgs.nix
    ];

    aos.abilities.stages.initrd = {
      packages = [pkgs.aos pkgs.systemd];
      intent = [
        {
          aos.metadata = {
            storageProvisioning.authorizationConfiguration = authorizationConfiguration;
            initrdServices = {
              enable = true;
              stashDir = cfg.stashDir;
              inherit trust;
              trustedConfigKeysDir = toString configTrustAnchors;
              baseLibrary = toString config.aos.config.evalAtBoot.baseLib;
              measuredBoot = measured;
            };
          };
        }
      ];
    };
  };
}
