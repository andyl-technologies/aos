##! Generated configuration companion for a package expose declaration.
##!
##! The fixed package builder copies this file as `module.nix` beside an
##! authenticated `expose-config.json`. It declares only the package-private
##! option root; packages never write a shared/internal projection root.
{
  config,
  lib,
  ...
}: let
  schema = builtins.fromJSON (builtins.readFile ./expose-config.json);
  package = schema.package;
  cfg = config.${package};
  credentialDeclaration = name: let
    declarations = builtins.filter (credential: credential.name == name) schema.config.credentials;
  in
    if builtins.length declarations == 1
    then builtins.head declarations
    else throw "credential reference '${package}.${name}' has no unique signed expose.config declaration";
  secretRefType = lib.types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9_.-]+";
        default = name;
        readOnly = true;
      };
      ref = lib.mkOption {
        type = lib.types.strMatching "(tpm2-credstore|desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?";
      };
    };
  });
in {
  options.${package} = {
    config = lib.mkOption {
      type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
      default = {};
      description = "Desired values for the package's declared config artifacts.";
    };

    credentials = lib.mkOption {
      type = lib.types.attrsOf secretRefType;
      default = {};
      description = "Opaque references for the package's declared credentials.";
    };

    _aosExposeConfigProjection = lib.mkOption {
      type = lib.types.attrs;
      internal = true;
      readOnly = true;
      description = "Authenticated package expose projection input.";
    };
  };

  config = {
    assertions =
      lib.mapAttrsToList (name: reference: let
        declaration = credentialDeclaration name;
      in {
        assertion = !(lib.hasPrefix "tpm2-credstore" reference.ref) || (declaration.encrypted or false);
        message = "credential reference '${package}.${name}' cannot use tpm2-credstore with a plaintext signed destination";
      })
      cfg.credentials;

    ${package}._aosExposeConfigProjection = {
      schema = "aos.expose-config-binding/v1";
      schema_hash = "sha256:${builtins.hashString "sha256" (builtins.toJSON schema.config)}";
      desired = cfg.config;
      credentials = lib.mapAttrs (name: reference: let
        declaration = credentialDeclaration name;
      in
        {
          inherit name;
          source = declaration.source or null;
          encrypted = declaration.encrypted or false;
          units = declaration.units or [];
          inherit (reference) ref;
        }
        // lib.optionalAttrs (declaration ? ciphertext) {
          inherit (declaration) ciphertext;
        })
      cfg.credentials;
    };
  };
}
