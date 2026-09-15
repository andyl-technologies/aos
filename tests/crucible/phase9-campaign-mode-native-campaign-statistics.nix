{
  pkgs,
  lib,
  ...
} @ args: let
  authority = import ./phase4-campaign-statistics.nix {inherit pkgs lib;};
in
  import ./phase9-campaign-mode-native-gate.nix (args
    // {
      gate = "gate:campaign-statistics";
      authoritativeAttr = "checks.crucible.phase4.gates.campaignStatistics";
      inherit authority;
      name = "native-campaign-statistics";
      cargoBuildCommands = [
        "test --frozen --offline --no-run -p crucible-campaign --lib --test gate_campaign_statistics"
      ];
      installedTests = [
        {
          targetName = "crucible_campaign";
          targetKind = "lib";
          crateDir = "crucible-campaign";
          destination = "crucible-campaign-lib";
        }
        {
          targetName = "gate_campaign_statistics";
          targetKind = "test";
          crateDir = "crucible-campaign";
          destination = "gate-campaign-statistics";
        }
      ];
      runtimeCommands = [
        {
          executable = "crucible-campaign-lib";
          arguments = ["policy::statistical::tests::finite_distribution_rejects_incomplete_or_nonpositive_mass_contracts" "--exact"];
          expectedCount = 1;
          evidence = "finite_distribution_contract";
        }
        {
          executable = "crucible-campaign-lib";
          arguments = ["repository::tests::statistics::statistical_design_requires_static_exhaustive_policy_and_unconfigured_reports_fail_closed" "--exact"];
          expectedCount = 1;
          evidence = "statistical_design_contract";
        }
        {
          executable = "crucible-campaign-lib";
          arguments = ["repository::tests::statistics::two_edge_statistical_flight_reports_the_full_unequal_probability_product" "--exact"];
          expectedCount = 1;
          evidence = "unequal_probability_product";
        }
        {
          executable = "crucible-campaign-lib";
          arguments = ["repository::tests::statistics::duplicate_draws_reuse_one_observation_without_losing_sampling_multiplicity" "--exact"];
          expectedCount = 1;
          evidence = "duplicate_draw_sampling";
        }
        {
          executable = "crucible-campaign-lib";
          arguments = ["repository::tests::statistics::smc"];
          expectedCount = 6;
          evidence = "bounded_smc_suite";
        }
        {
          executable = "gate-campaign-statistics";
          arguments = [];
          expectedCount = 2;
          evidence = "gate_campaign_statistics";
        }
      ];
    })
