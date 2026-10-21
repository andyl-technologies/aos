##! Cargo selections compiled by the Crucible workspace test builds.
##!
##! A selection is the package set, feature set, and profile of one Cargo
##! invocation. Cargo resolves features per invocation, so `cargo test -p
##! crucible` and `cargo test -p crucible --features test-double` compile
##! different units even inside one target directory. Each gate's former
##! Cargo command maps to exactly one selection here, and the build family
##! replays the same resolution once for every gate.
##!
##! Fields:
##!
##! ```text
##! packages    Cargo packages passed with -p (one for test selections)
##! features    features passed with --features (default [])
##! allTargets  also compile examples and benches as test harnesses
##! targets     Cargo target flags for build selections, such as --examples
##! ```
##!
##! A gate that needs a selection missing from this file fails with the
##! exact selection to add.
{
  # Apache-licensed host crates, debug test profile.
  apacheTests = [
    {packages = ["aos-ability-crucible"];}
    {
      packages = ["crucible"];
      # `cargo test --example phase5_live_asset_fixture` runs an example's tests.
      allTargets = true;
    }
    {
      packages = ["crucible"];
      features = ["test-double"];
    }
    {packages = ["crucible-api"];}
    {
      packages = ["crucible-api"];
      features = ["test-support"];
    }
    {packages = ["crucible-assert"];}
    {packages = ["crucible-campaign"];}
    {
      packages = ["crucible-campaign"];
      features = ["test-support"];
    }
    {packages = ["crucible-cas"];}
    {
      packages = ["crucible-cas"];
      features = ["destructive-recovery-faults"];
    }
    {
      packages = ["crucible-cas"];
      features = ["test-support"];
    }
    {packages = ["crucible-cli"];}
    {
      packages = ["crucible-cli"];
      features = ["destructive-recovery-faults"];
    }
    {
      packages = ["crucible-cli"];
      features = ["test-double"];
    }
    {packages = ["crucible-daemon"];}
    {
      packages = ["crucible-daemon"];
      features = ["test-support"];
    }
    {packages = ["crucible-device"];}
    {packages = ["crucible-guest"];}
    {packages = ["crucible-harness"];}
    {packages = ["crucible-linux-resource"];}
    {packages = ["crucible-protocol"];}
    {
      packages = ["crucible-qemu"];
      allTargets = true;
    }
    {
      packages = ["crucible-qemu"];
      features = ["test-support"];
      allTargets = true;
    }
    {packages = ["crucible-s3-store"];}
    {
      packages = ["crucible-session"];
      allTargets = true;
    }
    {packages = ["crucible-shmem"];}
    {packages = ["crucible-sim"];}
  ];

  # Apache-licensed executables built with `cargo build` or `cargo run` in
  # the development profile. Examples resolve dev-dependencies; plain
  # binaries do not, so each target class keeps its own selection.
  apacheBuilds = [
    {
      packages = ["crucible"];
      targets = ["--examples"];
    }
    {
      packages = ["crucible-guest"];
      targets = ["--bins"];
    }
    {
      packages = ["crucible-qemu"];
      targets = ["--examples"];
    }
    {
      packages = ["crucible-shmem"];
      targets = ["--examples"];
    }
  ];

  # Apache-licensed release executables consumed by VM flights.
  apacheReleaseBuilds = [
    {
      packages = ["crucible-cli"];
      targets = ["--bin crucible"];
    }
    {
      packages = ["crucible-cli"];
      features = ["packaged-midpoint-flight"];
      targets = ["--bin crucible"];
    }
    {
      packages = ["crucible-linux-resource"];
      targets = ["--examples"];
    }
    {
      packages = ["crucible-qemu"];
      targets = ["--examples"];
    }
  ];

  # The ack-poll experiments compile the same examples with test support.
  apacheReleaseTestSupportBuilds = [
    {
      packages = ["crucible-qemu"];
      features = ["test-support"];
      targets = ["--examples"];
    }
  ];

  # Release test harnesses copied into VM flights and campaign-mode guests.
  # `targets` narrows a selection to the harnesses those consumers copy.
  apacheReleaseTests = [
    {
      packages = ["crucible"];
      targets = ["--test gate_checkpoint_materialization" "--test gate_fork_replay_oracle"];
    }
    {
      packages = ["crucible"];
      features = ["test-support"];
      targets = ["--lib" "--test gate_basic_block_coverage"];
    }
    {
      packages = ["crucible-campaign"];
      targets = ["--lib" "--test gate_campaign_model"];
    }
    {
      packages = ["crucible-cli"];
      targets = ["--test campaign_process" "--test campaign_store_process"];
    }
    {
      packages = ["crucible-cli"];
      features = ["packaged-midpoint-flight"];
      targets = ["--test campaign_process" "--test campaign_store_process"];
    }
    {packages = ["crucible-daemon"];}
    {
      packages = ["crucible-qemu"];
      targets = ["--lib"];
    }
    {
      packages = ["crucible-api" "crucible-daemon" "crucible-qemu"];
      targets = ["--lib"];
    }
  ];

  # GPL-side process crates, debug test profile.
  gplTests = [
    {packages = ["crucible-debug-gateway"];}
    {packages = ["crucible-qemu-plugin"];}
  ];

  gplBuilds = [
    {
      packages = ["crucible-qemu-plugin"];
      targets = ["--lib"];
    }
  ];

  # GPL-side release test harnesses copied into campaign-mode guests.
  gplReleaseTests = [
    {
      packages = ["crucible-qemu-plugin"];
      targets = ["--lib"];
    }
  ];
}
