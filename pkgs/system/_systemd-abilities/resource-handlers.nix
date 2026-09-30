##! Selects native systemd handlers for instance mounts, swaps, timers, and credentials.
{
  lib,
  package,
  ...
}: let
  program = package // {meta = (package.meta or {}) // {mainProgram = "aos-systemd-native-resources";};};
  option = type: description: lib.mkOption {inherit type description;};
  defaulted = type: default: description: lib.mkOption {inherit type default description;};
  text = lib.types.str;
  deferredPath = lib.types.deferred text;
  nonnegative = lib.types.ints.unsigned;
  result = {
    resource = option text "Canonical systemd unit owned by this effect.";
  };
  schedule = lib.types.taggedUnion "kind" {
    calendar = lib.types.submodule {
      options = {
        kind = option (lib.types.enum ["calendar"]) "Calendar schedule discriminator.";
        expression = option text "Systemd calendar expression.";
      };
    };
    interval = lib.types.submodule {
      options = {
        kind = option (lib.types.enum ["interval"]) "Interval schedule discriminator.";
        initial_delay_millis = defaulted nonnegative 0 "Initial delay from host boot.";
        interval_millis = option lib.types.ints.positive "Interval between service activations.";
      };
    };
  };
in {
  aos.abilities = {
    swap.operations.ensure = {
      input.options = {
        name = option text "Human-readable swap description.";
        source = option deferredPath "Checked swap device or file path.";
        enabled = defaulted lib.types.bool true "Activate and enable this managed swap.";
        priority = defaulted (lib.types.nullOr lib.types.int) null "Optional kernel swap priority.";
      };
      result.options = result;
      handler.program = program;
    };
    mount.operations.ensure.handler.program = program;
    scheduledActivation.operations.ensure = {
      input.options = {
        name = option text "Human-readable scheduled activation description.";
        target = option deferredPath "Canonical service unit from its realization result.";
        schedule = option schedule "Calendar or interval activation policy.";
        persistent = defaulted lib.types.bool false "Catch up calendar events missed while inactive.";
        accuracy_millis = defaulted nonnegative 60000 "Allowed timer coalescing window.";
        randomized_delay_millis = defaulted nonnegative 0 "Maximum additional randomized delay.";
      };
      result.options = result;
      handler.program = program;
    };
    credential.operations.deliver.handler.program = program;
    identity.operations = {
      group.handler.program = program;
      principal.handler.program = program;
      membership.handler.program = program;
    };
    listener.operations.claim.handler.program = program;
    managerWatchdog.operations.ensure.handler.program = program;
    packagedUnit.operations.ensure.handler.program = program;
  };
}
