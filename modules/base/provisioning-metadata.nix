##! Configures package-owned typed metadata provisioning abilities.
{
  config,
  lib,
  pkgs,
  ...
}: let
  trust = config.aos.config.evalAtBoot.trust;
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
  config = {
    aos.metadata.storageProvisioning = {inherit authorizationConfiguration;};

    aos.boot.initrd.packageRoots = [
      pkgs.aos-metadata-provider
      pkgs.aos-nix-store-provider
      pkgs.nix
    ];
    aos.boot.initrd.nonPackageRuntimeArtifacts = [
      (builtins.toString configTrustAnchors)
      (builtins.toString config.aos.config.evalAtBoot.baseLib)
    ];
  };
}
