##! Defines manager-neutral group and principal creation contracts.
{lib, ...}: let
  name = lib.mkOption {
    type = lib.types.str;
    description = "Account name managed by this operation.";
  };
  allocation = lib.mkOption {
    type = lib.types.enum ["managed" "existing"];
    default = "managed";
    description = "Create the owned account or resolve an existing account without modifying it.";
  };
  requestedId = lib.mkOption {
    type = lib.types.nullOr lib.types.int;
    default = null;
    description = "Exact numeric account identity when required by packaged policy.";
  };
  result = {
    options = {
      name = lib.mkOption {
        type = lib.types.str;
        description = "Established account name.";
      };
      resource = lib.mkOption {
        type = lib.types.str;
        description = "Established account resource identity.";
      };
    };
  };
in {
  aos.abilities.identity.operations = {
    membership = {
      input.options = {
        mode = lib.mkOption {
          type = lib.types.enum ["add" "replace"];
          default = "add";
          description = "Add owned memberships or replace the exact member set of a provider-owned group.";
        };
        group = lib.mkOption {
          type = lib.types.deferred lib.types.str;
          description = "Existing group whose explicit members are granted membership.";
        };
        members = lib.mkOption {
          type = lib.types.listOf (lib.types.deferred lib.types.str);
          description = "Existing principals to add while preserving unrelated memberships.";
        };
      };
      result.options.resource = lib.mkOption {
        type = lib.types.str;
        description = "Established explicit group membership resource.";
      };
    };
    group = {
      input.options = {
        inherit name allocation;
        requested_id = requestedId;
      };
      inherit result;
    };
    principal = {
      input.options = {
        inherit name allocation;
        requested_id = requestedId;
        supplementary_groups = lib.mkOption {
          type = lib.types.listOf (lib.types.deferred lib.types.str);
          default = [];
          description = "Additional groups granted to this account.";
        };
        login_access = lib.mkOption {
          type = lib.types.enum ["disabled" "enabled"];
          default = "disabled";
          description = "Whether the account may use an interactive login shell.";
        };
        login_shell = lib.mkOption {
          type = lib.types.deferred (lib.types.nullOr lib.types.pathInStore);
          default = null;
          description = "Optional immutable login executable used when login access is enabled; otherwise the pinned defaults apply.";
        };
        primary_group = lib.mkOption {
          type = lib.types.nullOr (lib.types.deferred lib.types.str);
          default = null;
          description = "Primary group name, including a group operation result.";
        };
        home_directory = lib.mkOption {
          type = lib.types.str;
          default = "/var/empty";
          description = "Home directory recorded for the service account.";
        };
        description = lib.mkOption {
          type = lib.types.str;
          default = "";
          description = "Human-readable account purpose.";
        };
      };
      inherit result;
    };
  };
}
