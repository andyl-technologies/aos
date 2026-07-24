##! modules/base/apm-registries.nix — Baked registry trust anchors
##!
##! Declares `aos.apm.registries`, which bakes a registry configuration
##! and its initial trust anchor into the image:
##!
##!   - `/etc/apm/registries.d/<name>.toml` — registry URL, priority,
##!     and `[registry.signing]` with the first trust key as the
##!     bootstrap anchor.
##!   - `/etc/apm/trusted-keys.d/<name>.pub` — every trust key, one per
##!     line (`apm` reads this directory in both profile scopes).
##!   - `/etc/apm/trusted-sb-certs.d/<name>.pem` — the Secure Boot db
##!     certificate(s) `apm` re-verifies cataloged UKIs against at
##!     download time (RFC-0006 phase 4). Distinct key, same delivery
##!     mechanism as the registry trust anchor, provisioned at install.
##!   - `/etc/apm/trusted-config-keys.d/<op>.pub` — provisioning-signing
##!     key(s) (`aos.apm.configKeys`). Under signed provisioning policy, the
##!     initrd verifies the complete input against the same public anchors
##!     copied into its measured closure before extracting storage or host
##!     configuration.
##!
##! This is the out-of-band root of trust: first contact with the
##! registry verifies against these keys, and all later key rotation
##! flows in-band through the registry's signed git history. Updating
##! the baked anchor is an ordinary image rebuild; day-to-day rotation
##! reaches deployed machines on their next sync without an image
##! change.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.apm.registries;
  configKeys = config.aos.apm.configKeys;
  registryRenderer = import ./_apm-registry-renderer.nix {inherit lib;};
  inherit
    (registryRenderer)
    registryNamePattern
    registryToml
    registryType
    trustedKeys
    trustedSbCerts
    trustKeyPattern
    ;
  # An operator id is the `<op>.pub` filename stem and the `<op>:` prefix of
  # every trust line in that file — same grammar as a registry name.
  configKeyPattern = name: "${lib.escapeRegex name}:Ed25519:[A-Za-z0-9+/]+=*";
in {
  options.aos.apm.configKeys = lib.mkOption {
    default = {};
    description = ''
      Operator provisioning-signing keys for signed provisioning policy, baked
      into the image as
      `/etc/apm/trusted-config-keys.d/<op>.pub`. Each attribute name is an
      operator id; its value is a list of `<op>:Ed25519:<base64>` public key
      lines (rotation overlap is a multi-element list). In signed mode the
      initrd verifies the exact provisioning input in the `aos-provisioning`
      SSHSIG namespace before rendering a storage plan or exposing `host.nix`.
      Missing or untrusted signatures fail closed. Explicit off-boot
      `apm switch --require-signed-host-nix` operations use the same anchors
      with the narrower `aos-config` namespace.
    '';
    type = lib.types.attrsOf (lib.types.listOf lib.types.str);
  };

  options.aos.apm.registries = lib.mkOption {
    default.andyl = {
      url = "https://cdn.aos.andyl.org/";
      trustKeys = [
        "andyl:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIJiuCf/fX/rsn5ODyT5ebEVtabAmZceKi2aD+cBWjWKL" # louis@
      ];
    };
    description = ''
      Package registries baked into the image with their trust anchors.
      Each entry writes `/etc/apm/registries.d/<name>.toml` and
      `/etc/apm/trusted-keys.d/<name>.pub`, so `apm` verifies the
      registry out of the box without any manual `apr trust pin`.
    '';
    type = lib.types.attrsOf registryType;
  };

  config = {
    assertions = lib.flatten (lib.mapAttrsToList (
        name: registry:
          [
            {
              assertion = builtins.match registryNamePattern name != null;
              message = ''
                aos.apm.registries.${name}: registry names must match
                ${registryNamePattern} (ASCII letters, digits, '-' and '_').
              '';
            }
          ]
          ++ builtins.map (key: {
            assertion = builtins.match (trustKeyPattern name) key != null;
            message = ''
              aos.apm.registries.${name}: trust key '${key}' must be
              '${name}:Ed25519:<base64>' (the registry prefix has to match
              the attribute name).
            '';
          })
          registry.trustKeys
      )
      cfg)
    ++ lib.flatten (lib.mapAttrsToList (
        op: keys:
          [
            {
              assertion = builtins.match registryNamePattern op != null;
              message = ''
                aos.apm.configKeys.${op}: operator ids must match
                ${registryNamePattern} (ASCII letters, digits, '-' and '_').
              '';
            }
            {
              assertion = keys != [];
              message = ''
                aos.apm.configKeys.${op}: at least one '${op}:Ed25519:<base64>'
                key is required (an empty operator anchor trusts nothing).
              '';
            }
          ]
          ++ builtins.map (key: {
            assertion = builtins.match (configKeyPattern op) key != null;
            message = ''
              aos.apm.configKeys.${op}: config key '${key}' must be
              '${op}:Ed25519:<base64>' (the operator prefix has to match the
              attribute name).
            '';
          })
          keys
      )
      configKeys);

    environment.etc = lib.mkMerge (
      (lib.mapAttrsToList (name: registry:
        {
          "apm/registries.d/${name}.toml".text = registryToml name registry;
          "apm/trusted-keys.d/${name}.pub".text = trustedKeys registry;
        }
        // lib.optionalAttrs (registry.sbDbCerts != []) {
          "apm/trusted-sb-certs.d/${name}.pem".text = trustedSbCerts registry;
        })
      cfg)
      ++ (lib.mapAttrsToList (op: keys: {
        "apm/trusted-config-keys.d/${op}.pub".text =
          lib.concatMapStrings (key: key + "\n") keys;
      })
      configKeys)
    );
  };
}
