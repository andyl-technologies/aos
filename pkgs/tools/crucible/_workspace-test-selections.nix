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
##!              flags, and `cargoProfile` an optional --profile; a build
##!              that names examples resolves dev-dependencies exactly as the
##!              test command does, so it adds no recompiles
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
##! crucible-engine's test-double gates; crucible-cargo skips those targets for
##! that request, as Cargo does.
##!
##! Debug `cargo build` and `cargo run` requests are served from the test
##! profile, which inherits the development profile's debug assertions and
##! overflow checks and differs only in optimization level and debug info
##! (which collection strips anyway). Building them with the development
##! profile would compile every crate a second time.
##!
##! A gate request that no selection serves fails with the request to add.
{lib}: let
  # Apache host crates whose tests gates run in the debug profile.
  apacheDebugPackages = [
    "aos-activation-crucible"
    "crucible-campaign"
    "crucible-cli"
    "crucible-control-api"
    "crucible-control-client"
    "crucible-control-server"
    "crucible-daemon"
    "crucible-determinism"
    "crucible-device"
    "crucible-engine"
    "crucible-guest"
    "crucible-qemu-host"
    "crucible-qemu-protocol"
    "crucible-qemu-shmem"
    "crucible-session"
    "crucible-store"
    "crucible-store-s3"
    "crucible-test-support"
  ];

  # The dev-dependencies of those packages already enable test-support or
  # test-double on crucible-control-server, crucible-daemon,
  # crucible-engine, crucible-qemu-host, crucible-qemu-shmem,
  # crucible-session, and crucible-store. Gates request the remaining two
  # explicitly; neither has a feature-absent code path.
  apacheDebugFeatures = [
    "crucible-campaign/test-support"
    "crucible-session/test-double"
  ];

  # Release harnesses copied into VM flights and campaign-mode guests.
  apacheReleasePackages = [
    "crucible-campaign"
    "crucible-cli"
    "crucible-daemon"
    "crucible-engine"
    "crucible-qemu-host"
  ];
  apacheReleaseFeatures = ["crucible-engine/test-support"];
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
  # selection without crucible-qemu-host's test support.
  nonExampleKinds = ["lib" "bin" "test" "bench"];

  # Packages whose dev-dependencies enable crucible-qemu-host's test
  # support: crucible-daemon directly, and crucible-cli through
  # crucible-daemon's test support.
  qemuTestSupportPackages = ["crucible-cli" "crucible-daemon"];
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
          cargoProfile = "test";
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
          "aos-activation-crucible"
          "crucible-campaign"
          "crucible-campaign[test-support]"
          "crucible-cli"
          "crucible-control-api"
          "crucible-control-client"
          "crucible-control-server"
          "crucible-control-server[test-support]"
          "crucible-daemon"
          "crucible-daemon[test-support]"
          "crucible-determinism"
          "crucible-device"
          "crucible-engine"
          "crucible-engine[test-double]"
          "crucible-guest"
          {
            request = "crucible-qemu-host";
            kinds = nonExampleKinds;
          }
          "crucible-qemu-host[test-support]"
          "crucible-qemu-protocol"
          "crucible-qemu-shmem"
          "crucible-session"
          "crucible-store"
          "crucible-store-s3"
          "crucible-store[test-support]"
          "crucible-test-support"
        ];
        build = [
          "crucible-engine"
          "crucible-guest"
          "crucible-qemu-shmem"
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
    # crucible-store, so both gate requests share this one resolution. It
    # changes crucible-store, under nearly every Crucible crate, so the
    # selection names only the two requested packages: their lib and test
    # targets are all it compiles beyond the libraries.
    {
      id = "destructive-recovery-faults";
      packages = ["crucible-cli" "crucible-store"];
      features = ["crucible-cli/destructive-recovery-faults"];
      invocations = [
        {
          command = "test";
          targets = ["--lib" "--test campaign_store_process"];
        }
      ];
      collect = ["crucible-cli" "crucible-store"];
      serves.test = [
        {
          request = "crucible-store[destructive-recovery-faults]";
          kinds = ["lib"];
        }
        {
          request = "crucible-cli[destructive-recovery-faults]";
          kinds = ["test"];
        }
      ];
    }

    # Conflict: crucible-qemu-host's production examples take
    # cfg(not(feature = "test-support")) paths, and their tests assert that
    # behavior; the unified build enables test-support through the
    # dev-dependencies of crucible-cli and crucible-daemon. Leaving those
    # two out, and enabling the control-server test support only
    # crucible-daemon's test support supplied, keeps every other
    # first-party feature as in the unified build. Cargo cannot enable the
    # third-party feature only crucible-cli needs (rustix termios), so every
    # crate that links rustix recompiles here as well, crucible-store and the
    # Crucible crates above it among them.
    {
      id = "qemu-production-examples";
      packages = lib.subtractLists qemuTestSupportPackages apacheDebugPackages;
      features = apacheDebugFeatures ++ ["crucible-control-server/test-support"];
      invocations = [
        {
          command = "test";
          targets = ["--example crucible-qemu-production-plugin-flight"];
        }
        {
          command = "build";
          cargoProfile = "test";
          targets = ["--example crucible-qemu-live-block-realization"];
        }
      ];
      collect = ["crucible-qemu-host"];
      serves = {
        test = [
          {
            request = "crucible-qemu-host";
            kinds = ["example"];
          }
        ];
        build = ["crucible-qemu-host"];
      };
    }
  ];

  # GPL-side process crates, debug test profile.
  gplTests = [
    {
      id = "tests";
      packages = ["crucible-qemu-debug-gateway" "crucible-qemu-plugin"];
      invocations = [
        {
          command = "test";
          targets = ["--lib" "--bins" "--tests"];
        }
      ];
      doctests = true;
      serves.test = ["crucible-qemu-debug-gateway" "crucible-qemu-plugin"];
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
        # The ack-poll experiments run these examples with
        # crucible-qemu-host's test support, which this resolution already
        # enables.
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
          "crucible-campaign"
          "crucible-cli"
          "crucible-daemon"
          "crucible-daemon+crucible-qemu-host"
          "crucible-engine"
          "crucible-engine[test-support]"
          "crucible-qemu-host"
        ];
        build = [
          {
            request = "crucible-qemu-host[test-support]";
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
    # out dev-dependencies, so crucible-daemon keeps its production checks,
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

    # Conflict: the controller package ships these examples as `cargo build
    # --release -p <package> --example <name>` builds them. Each resolves
    # only its own package's dev-dependencies, so neither may unify with the
    # other or with the test resolution; crucible-daemon's
    # dev-dependencies, for example, enable crucible-engine's test-double
    # backend, and the test resolution also enables crucible-daemon's own
    # test support.
    {
      id = "controller-debugger-example";
      packages = ["crucible-engine"];
      invocations = [
        {
          command = "build";
          targets = ["--example crucible-debugger-live-fixture"];
        }
      ];
      serves.build = [
        {
          request = "crucible-engine";
          kinds = ["example"];
        }
      ];
    }
    {
      id = "controller-scenario-example";
      packages = ["crucible-daemon"];
      invocations = [
        {
          command = "build";
          targets = ["--example crucible-e2e-determinism-scenario"];
        }
      ];
      serves.build = [
        {
          request = "crucible-daemon";
          kinds = ["example"];
        }
      ];
    }

    # Conflict: the production examples take cfg(not(feature =
    # "test-support")) paths in crucible-qemu-host, which the test
    # resolution enables.
    {
      id = "production-examples";
      packages = ["aos-linux-project-quota" "crucible-qemu-host"];
      invocations = [
        {
          command = "build";
          targets = ["--examples"];
        }
      ];
      serves.build = ["aos-linux-project-quota" "crucible-qemu-host"];
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
