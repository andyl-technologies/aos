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
in {
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
      cfg);

    environment.etc = lib.mkMerge (lib.mapAttrsToList (name: registry:
      {
        "apm/registries.d/${name}.toml".text = registryToml name registry;
        "apm/trusted-keys.d/${name}.pub".text = trustedKeys registry;
      }
      // lib.optionalAttrs (registry.sbDbCerts != []) {
        "apm/trusted-sb-certs.d/${name}.pem".text = trustedSbCerts registry;
      })
    cfg);
  };
}
