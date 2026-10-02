##! Owns native local database convergence and persistent content objects.
{
  config,
  lib,
  package,
  ...
}: let
  database = config.aos.abilities.nixStoreDatabase.operations.converge;
  cfg = config.aos.nixStore;
  # Containers register their baked store in their entry point. The host's
  # persistent profile bridge belongs only to host activation.
  hostRuntime =
    cfg.enable
    && (config.aos.boot.stage or "host") == "host"
    && lib.take 1 config.aos.activation.scope != ["container"];
  configuration = config.aos.abilities.configuration.operations.file.effects.nix-store;
  profiles = config.aos.abilities.filesystem.operations.view.effects.nix-profiles;
  roots = config.aos.abilities.filesystem.operations.directory.effects.nix-profile-gcroots;
  bridge = config.aos.abilities.mount.operations.ensure.effects.nix-profile-gcroots;
in {
  options.aos.nixStore = lib.mkOption {
    extensible = true;
    type = lib.types.submodule [
      database.input
      {options.enable = lib.mkEnableOption "local Nix store integration";}
    ];
    default = {};
    description = "Merged local package-store configuration.";
  };

  config = lib.mkMerge [
    {
      aos.abilities.nixStoreDatabase.operations.converge = {
        input.options = {
          scope = lib.mkOption {
            type = lib.types.enum ["local"];
            default = "local";
            description = "Local Nix store database scope.";
          };
          registration = lib.mkOption {
            type = lib.types.nullOr (lib.types.submodule {
              options = {
                path = lib.mkOption {
                  type = lib.types.deferred lib.types.str;
                  description = "Exact registration stream supplied by the image or another operation.";
                };
                sha256 = lib.mkOption {
                  type = lib.types.nullOr (lib.types.deferred lib.types.str);
                  default = null;
                  description = "Digest of the exact retained stream; required for mutable image paths.";
                };
                required = lib.mkOption {
                  type = lib.types.bool;
                  default = true;
                  description = "Reject convergence when the registration stream is absent.";
                };
              };
            });
            default = null;
            description = "Image registration to import into the local database.";
          };
        };
        result.options = {
          resource = lib.mkOption {
            type = lib.types.str;
            description = "Converged local database readiness identity.";
          };
          registration_digest = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            description = "Digest of the exact imported registration stream.";
          };
        };
        handler.program = package;
      };
      aos.abilities.contentAddressedObject.operations.commit = {
        input.options = {
          name = lib.mkOption {
            type = lib.types.str;
            description = "Logical content object name.";
          };
          media_type = lib.mkOption {
            type = lib.types.str;
            description = "Canonical media type of the exact content.";
          };
          content = lib.mkOption {
            type = lib.types.deferred lib.types.str;
            description = "Exact UTF-8 content retained as an immutable flat object.";
          };
        };
        result.options = {
          path = lib.mkOption {
            type = lib.types.str;
            description = "Immutable committed store object path.";
          };
          content_sha256 = lib.mkOption {
            type = lib.types.str;
            description = "Digest of the exact committed bytes.";
          };
        };
        handler.program = package;
      };
    }
    {
      aos.abilities = {
        configuration.operations.file.effects.nix-store = lib.mkIf hostRuntime {
          input = {
            path = "/etc/nix/nix.conf";
            content = "# Managed by the selected AOS package-store provider.\nbuild-users-group =\n";
            mode = "0444";
          };
        };
        filesystem.operations = {
          # The boot substrate owns and seeds the profile tree. Host convergence
          # consumes that existing root without claiming or deleting its storage.
          view.effects.nix-profiles = lib.mkIf hostRuntime {
            input.sourcePath = "/var/lib/profiles";
          };
          directory.effects.nix-profile-gcroots = lib.mkIf hostRuntime {
            input = {
              path = "/nix/var/nix/gcroots/aos-profiles";
              mode = "0755";
              owner = "root";
              group = "root";
            };
          };
        };
        mount.operations.ensure.effects.nix-profile-gcroots = lib.mkIf hostRuntime {
          input = {
            name = "aos-profile-gcroots";
            source = profiles.outputs.path;
            destination = roots.outputs.path;
            options = ["bind"];
          };
        };
        nixStoreDatabase.operations.converge.effects.runtime = lib.mkIf hostRuntime {
          input = builtins.removeAttrs cfg ["enable"];
          after = [configuration.outputs.resource bridge.outputs.resource];
        };
      };
    }
  ];
}
