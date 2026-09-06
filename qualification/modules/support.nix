##! Declares how long each stable release train receives updates.
#
# Support is a forward-looking promise, distinct from the evidence that a
# release passed its gates. It is reviewed with the rest of the qualification
# contract, exported with it, and copied verbatim into the signed registry's
# `[support]` table so consumers and Hubs read the same statement.
{
  config,
  lib,
  ...
}: let
  cfg = config.qualification.support;
  types = import ./_types.nix {inherit lib;};
  kinds = ["standard" "lts"];
  # `major.minor` with no leading zeros, matching the calendar-train versions.
  trainPattern = "(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)";
  datePattern = "[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])";
  matches = pattern: value: builtins.match pattern value != null;
  train = types.closed {
    kind = (types.option (lib.types.enum kinds) "Support class of the train.") // {default = "standard";};
    supported_until =
      (types.option (lib.types.nullOr lib.types.str) "Last day of support as an ISO-8601 date; absent means until superseded.")
      // {default = null;};
  };
in {
  options.qualification.support = {
    default = lib.mkOption {
      type = types.closed {
        kind = (types.option (lib.types.enum kinds) "Support class of trains without an explicit entry.") // {default = "standard";};
        superseded_after_trains =
          (types.option types.positive "Number of newer stable trains after which an implicit train reaches end of life.")
          // {default = 2;};
      };
      default = {};
      description = "Support applied to stable trains that have no explicit entry.";
    };
    trains = lib.mkOption {
      type = lib.types.attrsOf train;
      default = {};
      description = "Explicit per-train support statements keyed by `major.minor`.";
    };
  };
  config.qualification.assertions = [
    {
      assertion = cfg.default.superseded_after_trains >= 1;
      message = "The rolling support default must keep at least one newer train before end of life.";
    }
    {
      assertion = builtins.all (matches trainPattern) (builtins.attrNames cfg.trains);
      message = "Support train keys must be major.minor without leading zeros.";
    }
    {
      assertion = builtins.all (name: let
        entry = cfg.trains.${name};
      in
        entry.supported_until == null || matches datePattern entry.supported_until)
      (builtins.attrNames cfg.trains);
      message = "Support end dates must be ISO-8601 calendar dates (YYYY-MM-DD).";
    }
    {
      assertion = builtins.all (name: let
        entry = cfg.trains.${name};
      in
        entry.kind != "lts" || entry.supported_until != null)
      (builtins.attrNames cfg.trains);
      message = "Long-term-support trains must state their supported_until date.";
    }
  ];
}
