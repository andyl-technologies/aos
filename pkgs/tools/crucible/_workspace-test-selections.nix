##! Cargo selections compiled by the Crucible workspace test builds.
##!
##! A selection is one Cargo feature resolution: a package set, a feature
##! set, and a profile. Cargo resolves features once per invocation and
##! unifies them across every selected package and its dev-dependencies, so
##! each extra resolution recompiles every first-party crate whose features
##! differ. Each family therefore builds one unified selection per profile
##! and adds a selection only where unifying would change what a test
##! observes. Every extra selection states that conflict below.
##!
##! Fields:
##!
##! ```text
##! id           selection name published in the family manifest
##! packages     packages passed with -p; they fix the feature resolution
##! features     package-qualified features passed with --features
##! invocations  Cargo commands sharing that resolution: `command` is test
##!              (compiled with --no-run) or build, `targets` its target
##!              flags; a build that names examples resolves dev-dependencies
##!              exactly as the test command does, so it adds no recompiles
##! collect      packages whose executables are published (default packages)
##! doctests     run and record doctests for the selected packages
##! serves       gate requests this selection answers, keyed by mode:
##!              `test` for `cargo test`, `build` for `cargo build`/`run`.
##!              A request is crucible-cargo's identity: sorted packages
##!              joined by +, then sorted requested features in brackets. An
##!              entry is the request string, or { request; kinds; } to
##!              answer only some target kinds.
##! ```
##!
##! Unifying features keeps each test's behavior because the Crucible crates
##! gate test-only code additively: `test-support` and `test-double` add
##! items and fixtures. The exceptions are the conflicts listed with the
##! extra selections. A unified build also compiles test targets whose
##! `required-features` a gate's own request would not enable, such as
##! crucible's test-double gates; crucible-cargo skips those targets for that
##! request, as Cargo does.
##!
##! A gate request that no selection serves fails with the request to add.
let
  # Apache host crates whose tests gates run in the debug profile.
  apacheDebugPackages = [
    "aos-ability-crucible"
    "crucible"
    "crucible-api"
    "crucible-campaign"
    "crucible-cas"
    "crucible-cli"
    "crucible-daemon"
    "crucible-device"
    "crucible-guest"
    "crucible-harness"
    "crucible-protocol"
    "crucible-qemu"
    "crucible-s3-store"
    "crucible-session"
    "crucible-shmem"
    "crucible-sim"
  ];

  # The dev-dependencies of those packages already enable test-support or
  # test-double on crucible, crucible-api, crucible-cas, crucible-daemon,
  # crucible-qemu, crucible-session, and crucible-shmem. Gates request the
  # remaining two explicitly; neither has a feature-absent code path.
  apacheDebugFeatures = [
    "crucible-campaign/test-support"
    "crucible-session/test-double"
  ];

  # Release harnesses copied into VM flights and campaign-mode guests.
  apacheReleasePackages = [
    "crucible"
    "crucible-api"
    "crucible-campaign"
    "crucible-cli"
    "crucible-daemon"
    "crucible-qemu"
  ];
  apacheReleaseFeatures = ["crucible/test-support"];
  apacheReleaseTargets = [
    "--lib"
    "--test gate_basic_block_coverage"
    "--test gate_campaign_metadata_million"
    "--test gate_campaign_model"
    "--test gate_checkpoint_materialization"
    "--test gate_fork_replay_oracle"
    "--test campaign_process"
    "--test campaign_store_process"
  ];
  cliProcessTests = ["--test campaign_process" "--test campaign_store_process"];

  # Every kind except examples, for packages whose examples come from a
  # selection without crucible-qemu's test support.
  nonExampleKinds = ["lib" "bin" "test" "bench"];
in {
  # Apache host crates, debug test profile.
  apacheTests = [
    {
      id = "tests";
      packages = apacheDebugPackages;
      features = apacheDebugFeatures;
      invocations = [
        {
          command = "test";
          targets = [
            "--lib"
            "--bins"
            "--tests"
            "--example phase5_live_asset_fixture"
            "--example crucible-qemu-production-plugin-flight"
          ];
        }
        {
          command = "build";
          targets = [
            "--bins"
            "--example phase5_live_asset_fixture"
            "--example crucible-shmem-abi-header"
          ];
        }
      ];
      doctests = true;
      serves = {
        test = [
          "aos-ability-crucible"
          "crucible"
          "crucible[test-double]"
          "crucible-api"
          "crucible-api[test-support]"
          "crucible-campaign"
          "crucible-campaign[test-support]"
          "crucible-cas"
          "crucible-cas[test-support]"
          "crucible-cli"
          "crucible-daemon"
          "crucible-daemon[test-support]"
          "crucible-device"
          "crucible-guest"
          "crucible-harness"
          "crucible-protocol"
          {
            request = "crucible-qemu";
            kinds = nonExampleKinds;
          }
          "crucible-qemu[test-support]"
          "crucible-s3-store"
          "crucible-session"
          "crucible-shmem"
          "crucible-sim"
        ];
        build = [
          "crucible"
          "crucible-guest"
          "crucible-shmem"
        ];
      };
    }

    # Conflict: crucible-cli's help_surface tests assert, under
    # cfg(not(feature = "test-double")), that the production CLI rejects the
    # test-double options, and the CLI's run paths switch on the same cfg.
    # The selection adds only that feature to the unified resolution, so it
    # recompiles crucible-cli alone.
    {
      id = "cli-test-double";
      packages = apacheDebugPackages;
      features = apacheDebugFeatures ++ ["crucible-cli/test-double"];
      invocations = [
        {
          command = "test";
          targets = ["--lib" "--bins" "--tests"];
        }
      ];
      collect = ["crucible-cli"];
      serves.test = ["crucible-cli[test-double]"];
    }

    # Conflict: destructive-recovery-faults compiles fault-injection tests
    # that arm process-wide triggers and change store recovery paths. The
    # CLI feature enables it on crucible-daemon, crucible-campaign, and
    # crucible-cas, so both gate requests share this one resolution.
    {
      id = "destructive-recovery-faults";
      packages = apacheDebugPackages;
      features = apacheDebugFeatures ++ ["crucible-cli/destructive-recovery-faults"];
      invocations = [
        {
          command = "test";
          targets = ["--lib" "--test campaign_store_process"];
        }
      ];
      collect = ["crucible-cas" "crucible-cli"];
      serves.test = [
        {
          request = "crucible-cas[destructive-recovery-faults]";
          kinds = ["lib"];
        }
        {
          request = "crucible-cli[destructive-recovery-faults]";
          kinds = ["test"];
        }
      ];
    }

    # Conflict: crucible-qemu's production examples take cfg(not(feature =
    # "test-support")) paths, and their tests assert that behavior; the
    # unified build enables test-support through its dev-dependencies.
    # crucible/test-support matches the unified crucible so only
    # crucible-qemu recompiles.
    {
      id = "qemu-production-examples";
      packages = ["crucible-qemu"];
      features = ["crucible/test-support"];
      invocations = [
        {
          command = "test";
          targets = ["--example crucible-qemu-production-plugin-flight"];
        }
        {
          command = "build";
          targets = ["--example crucible-qemu-live-block-realization"];
        }
      ];
      serves = {
        test = [
          {
            request = "crucible-qemu";
            kinds = ["example"];
          }
        ];
        build = ["crucible-qemu"];
      };
    }
  ];

  # GPL-side process crates, debug test profile.
  gplTests = [
    {
      id = "tests";
      packages = ["crucible-debug-gateway" "crucible-qemu-plugin"];
      invocations = [
        {
          command = "test";
          targets = ["--lib" "--bins" "--tests"];
        }
      ];
      doctests = true;
      serves.test = ["crucible-debug-gateway" "crucible-qemu-plugin"];
    }

    # Conflict: the plugin cdylib is the artifact QEMU loads. A plain build
    # leaves out the dev-dependencies, whose features a test build would
    # otherwise unify into the plugin's dependencies.
    {
      id = "plugin";
      packages = ["crucible-qemu-plugin"];
      invocations = [
        {
          command = "build";
          targets = ["--lib"];
        }
      ];
      serves.build = ["crucible-qemu-plugin"];
    }
  ];

  # Apache release executables and test harnesses consumed by VM flights.
  apacheRelease = [
    {
      id = "tests";
      packages = apacheReleasePackages;
      features = apacheReleaseFeatures;
      invocations = [
        {
          command = "test";
          targets = apacheReleaseTargets;
        }
        # The ack-poll experiments run these examples with crucible-qemu's
        # test support, which this resolution already enables.
        {
          command = "build";
          targets = [
            "--example crucible-qemu-production-plugin-flight"
            "--example crucible-qemu-rom-clamp-stress"
          ];
        }
      ];
      serves = {
        test = [
          "crucible"
          "crucible[test-support]"
          "crucible-api+crucible-daemon+crucible-qemu"
          "crucible-campaign"
          "crucible-cli"
          "crucible-daemon"
          "crucible-qemu"
        ];
        build = [
          {
            request = "crucible-qemu[test-support]";
            kinds = ["example"];
          }
        ];
      };
    }

    # Conflict: packaged-midpoint-flight changes the CLI's campaign process
    # behavior. Only crucible-cli has the feature, so it alone recompiles.
    {
      id = "cli-midpoint-tests";
      packages = apacheReleasePackages;
      features = apacheReleaseFeatures ++ ["crucible-cli/packaged-midpoint-flight"];
      invocations = [
        {
          command = "test";
          targets = cliProcessTests;
        }
      ];
      collect = ["crucible-cli"];
      serves.test = ["crucible-cli[packaged-midpoint-flight]"];
    }

    # Conflict: the flights qualify the CLI as shipped. A plain build leaves
    # out dev-dependencies, so crucible-api keeps its production checks,
    # which test-support relaxes.
    {
      id = "cli";
      packages = ["crucible-cli"];
      invocations = [
        {
          command = "build";
          targets = ["--bin crucible"];
        }
      ];
      serves.build = ["crucible-cli"];
    }

    # The shipped CLI with the midpoint flight hook; only crucible-cli
    # recompiles relative to `cli`.
    {
      id = "cli-midpoint";
      packages = ["crucible-cli"];
      features = ["crucible-cli/packaged-midpoint-flight"];
      invocations = [
        {
          command = "build";
          targets = ["--bin crucible"];
        }
      ];
      serves.build = ["crucible-cli[packaged-midpoint-flight]"];
    }

    # Conflict: the production examples take cfg(not(feature =
    # "test-support")) paths in crucible-qemu, which the test resolution
    # enables.
    {
      id = "production-examples";
      packages = ["crucible-linux-resource" "crucible-qemu"];
      invocations = [
        {
          command = "build";
          targets = ["--examples"];
        }
      ];
      serves.build = ["crucible-linux-resource" "crucible-qemu"];
    }
  ];

  # GPL-side release test harnesses copied into campaign-mode guests.
  gplRelease = [
    {
      id = "tests";
      packages = ["crucible-qemu-plugin"];
      invocations = [
        {
          command = "test";
          targets = ["--lib"];
        }
      ];
      serves.test = ["crucible-qemu-plugin"];
    }
  ];
}
