##! Owns the publication destinations and the profile each one selects.
#
# A destination is one (surface role, registry tier, channel kind) triple. The
# exported table is closed: anything not listed here is not a destination and
# plan validation rejects it. The registry tier decides which channels exist:
# the main registry carries every kind, so the integration stream ships through
# the same keys and pipeline as supported releases, while the testing
# registries carry edge only. A channel kind selects the same profile on both
# tiers, because the tier changes the infrastructure behind a release, not
# what the release must prove.
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

  otherTier = tier:
    if tier == "production"
    then "testing"
    else "production";

  sameProfile = row:
    cfg.destinations."${row.surface}/${otherTier row.registry_tier}/${row.channel}".profile == row.profile;

  # An undeclared profile is reported by its own assertion; here it counts as
  # unreviewed so the two messages do not depend on evaluation order.
  reviewedClaims = row:
    builtins.hasAttr row.profile cfg.profiles
    && (cfg.profiles.${row.profile}.claims == "none" || cfg.profiles.${row.profile}.review_threshold > 0);
in {
  options.qualification.destinations = lib.mkOption {
    type = lib.types.attrsOf types.destination;
    default = {};
    description = "Publication destinations keyed by `<surface>/<registry_tier>/<channel>`.";
  };

  config.qualification = {
    destinations = {
      "staging/testing/edge" = destination "staging" "testing" "edge" "build";
      "staging/production/edge" = destination "staging" "production" "edge" "build";
      "staging/production/candidate" = destination "staging" "production" "candidate" "build";
      "staging/production/stable" = destination "staging" "production" "stable" "build";
      "production/testing/edge" = destination "production" "testing" "edge" "smoke";
      "production/production/edge" = destination "production" "production" "edge" "smoke";
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
        # Supported channels publish assurance claims only after a human
        # review; edge makes no support promise and may rest on automated
        # evidence alone.
        assertion = builtins.all (row: row.channel == "edge" || reviewedClaims row) destinations;
        message = "Candidate and stable destinations with claims require at least one reviewer.";
      }
      {
        assertion = builtins.all (row: cfg.destinations ? "${row.surface}/${otherTier row.registry_tier}/${row.channel}" -> sameProfile row) destinations;
        message = "A channel kind selects the same profile on every tier that carries it.";
      }
      {
        assertion = builtins.all orderedAfterStaging destinations;
        message = "Destination prerequisites may name only the staging surface.";
      }
    ];
  };
}
