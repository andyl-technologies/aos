##! Retains metadata authorization policy and signing anchors in native source.
{
  config,
  lib,
  ...
}: let
  keys = config.aos.apm.configKeys;
  operatorPattern = "[A-Za-z0-9_-]+";
  keyPattern = operator: "${lib.escapeRegex operator}:Ed25519:[A-Za-z0-9+/]+=*";
in {
  options.aos.config.evalAtBoot = {
    trust = lib.mkOption {
      type = lib.types.enum ["platform" "signed"];
      default = "platform";
      description = ''
        Authentication policy for the delivered `host.nix`.

        `platform` trusts configuration obtained by the initrd metadata agent
        from the deployment platform. This is the default for cloud images:
        control of instance user-data is already part of the cloud control
        plane's authority, so one unmodified golden image can configure every
        instance.

        `signed` is the fail-closed mode for deployments that do not trust
        their metadata transport. The initrd verifies the complete provisioning
        input against `aos.apm.configKeys` before any storage mutation. Missing
        keys, missing signatures, and invalid signatures all prevent boot-time
        provisioning.
      '';
    };
  };
  options.aos.apm.configKeys = lib.mkOption {
    default = {};
    description = ''
      Operator host-configuration signing keys for signed policy, baked
      into the image as
      `/etc/apm/trusted-config-keys.d/<op>.pub`. Each attribute name is an
      operator id; its value is a list of `<op>:Ed25519:<base64>` public key
      lines (rotation overlap is a multi-element list). In signed mode the
      initrd verifies the exact `host.nix` bytes in the `aos-config` SSHSIG
      namespace before either restricted or full evaluation.
      Missing or untrusted signatures fail closed. Explicit off-boot
      `apm switch --require-signed-host-nix` operations use the same anchors
      with the same domain-separated namespace.
    '';
    type = lib.types.attrsOf (lib.types.listOf lib.types.str);
  };

  config.assertions =
    [
      {
        assertion = config.aos.config.evalAtBoot.trust != "signed" || keys != {};
        message = "Signed metadata authorization requires an operator configuration trust anchor.";
      }
    ]
    ++ lib.concatLists (lib.mapAttrsToList (operator: anchors:
      [
        {
          assertion = builtins.match operatorPattern operator != null;
          message = "Configuration signing operator names must contain only ASCII letters, digits, underscore, or dash.";
        }
        {
          assertion = anchors != [];
          message = "Configuration signing operator ${operator} requires a nonempty public key anchor list.";
        }
      ]
      ++ map (key: {
        assertion = builtins.match (keyPattern operator) key != null;
        message = "Configuration signing keys must use the matching operator:Ed25519:base64 identity.";
      })
      anchors)
    keys);
}
