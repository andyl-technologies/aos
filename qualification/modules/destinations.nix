##! Owns the publication destinations and the profile each one selects.
#
# A destination is one (surface role, registry tier, channel kind) triple. The
# exported table is closed: anything not listed here is not a destination and
# plan validation rejects it. The registry tier decides which channels exist,
# because the testing registries carry edge only and the main registry never
# publishes edge.
{
  config,
  lib,
  ...
}: let
  cfg = config.qualification;
  types = import ./_types.nix {inherit lib;};

  # Attribute keys double as the destination identity, so the key must agree
  # with the row; uniqueness then follows from attribute-set semantics.
  key = destination: "${destination.surface}/${destination.registry_tier}/${destination.channel}";

  destination = surface: registry_tier: channel: profile: {
    inherit surface registry_tier channel profile;
    # Production surfaces publish only what staging already holds.
    after = lib.optional (surface == "production") "staging";
  };

  # Only staging can precede another surface, and a staging destination
  # cannot wait on itself.
  orderedAfterStaging = row:
    builtins.all (role: role == "staging") row.after && (row.surface != "staging" || row.after == []);

  destinations = builtins.attrValues cfg.destinations;
in {
  options.qualification.destinations = lib.mkOption {
    type = lib.types.attrsOf types.destination;
    default = {};
    description = "Publication destinations keyed by `<surface>/<registry_tier>/<channel>`.";
  };

  config.qualification = {
    destinations = {
      "staging/testing/edge" = destination "staging" "testing" "edge" "build";
      "staging/production/candidate" = destination "staging" "production" "candidate" "build";
      "staging/production/stable" = destination "staging" "production" "stable" "build";
      "production/testing/edge" = destination "production" "testing" "edge" "smoke";
      "production/production/candidate" = destination "production" "production" "candidate" "functional";
      "production/production/stable" = destination "production" "production" "stable" "soak";
    };

    assertions = [
      {
        assertion = builtins.all (name: key cfg.destinations.${name} == name) (builtins.attrNames cfg.destinations);
        message = "Destination keys must equal `<surface>/<registry_tier>/<channel>`.";
      }
      {
        assertion = builtins.all (row: builtins.hasAttr row.profile cfg.profiles) destinations;
        message = "Destinations must select a declared profile.";
      }
      {
        assertion = builtins.all (row: row.registry_tier != "testing" || row.channel == "edge") destinations;
        message = "Testing registries carry the edge channel only.";
      }
      {
        assertion = builtins.all (row: row.registry_tier != "production" || row.channel != "edge") destinations;
        message = "The production registry never publishes edge.";
      }
      {
        assertion = builtins.all orderedAfterStaging destinations;
        message = "Destination prerequisites may name only the staging surface.";
      }
    ];
  };
}
