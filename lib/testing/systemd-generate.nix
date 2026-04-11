# lib/testing/systemd-generate.nix — Stage-3 full-pipeline check.
#
# Drives `modules/systemd/system.nix` end-to-end: declare a handful of
# representative services / timers via the typed `systemdNew.*` options,
# evalModules with the real system.nix module, force-build the resulting
# `system.build.systemdNewSystemUnits` derivation, and inspect its output
# directory to assert that every expected file and symlink was produced.
#
# Complements `lib/testing/systemd-lib.nix`, which tests the individual
# `*-ToUnit` renderers and the `script → ExecStart` compilation in
# isolation. This file exercises the glue between those renderers,
# `generateUnits`, and the actual `$out/etc/systemd/system/` layout so
# that stage 4's consumer swap in `modules/base/build.nix` can proceed
# confident that `${config.system.build.systemdSystemUnits}` produces a
# well-formed directory.
#
# Runs via `nix-build -A checks.systemd-generate`.
{
  pkgs,
  lib,
}: let
  systemdModule = import ../../modules/systemd/system.nix;

  # Minimal module set: just system.nix plus a synthetic config module
  # that declares a handful of services covering the patterns we care
  # about at stage 3. Deliberately does NOT pull in the whole AOS
  # module tree — we want this check to fail in a way that points at
  # system.nix / _lib.nix / _unit-options.nix, not at an unrelated
  # module deep in modules/services/.
  syntheticConfig = {
    config.systemdNew = {
      # A plain service with a compiled script.
      services.hello-world = {
        description = "Hello world stage-3 service";
        wantedBy = ["multi-user.target"];
        after = ["network.target"];
        serviceConfig.Type = "oneshot";
        script = "echo hello from stage 3";
      };

      # A service with direct ExecStart and a required dependency.
      services.with-requires = {
        description = "Service with direct ExecStart and Requires=";
        wantedBy = ["multi-user.target"];
        requires = ["network-online.target"];
        serviceConfig = {
          Type = "simple";
          ExecStart = "/bin/true";
        };
      };

      # A timer that schedules a service.
      timers.periodic = {
        description = "Periodic timer";
        wantedBy = ["timers.target"];
        timerConfig = {
          OnBootSec = "5min";
          OnUnitActiveSec = "10min";
          Unit = "hello-world.service";
        };
      };

      # A target with dependencies.
      targets.my-target = {
        description = "Custom target";
        wants = ["hello-world.service"];
      };
    };
  };

  result = lib.evalModules {
    modules = [systemdModule syntheticConfig];
    inherit pkgs lib;
  };

  systemUnits = result.config.system.build.systemdNewSystemUnits;

  # Pull out the rendered unit texts at eval time so we can include
  # spot-checks at build time without having to grep the output dir
  # for every single assertion.
  helloService = result.config.systemdNew.units."hello-world.service".text;
  withRequiresService = result.config.systemdNew.units."with-requires.service".text;
  periodicTimer = result.config.systemdNew.units."periodic.timer".text;
  myTarget = result.config.systemdNew.units."my-target.target".text;

  containsStr = needle: haystack:
    builtins.match ".*${lib.escapeRegex needle}.*" haystack != null;

  evalAssertions =
    # hello-world.service: script compiled → ExecStart points at store path
    lib.throwIfNot
    (containsStr "Description=Hello world stage-3 service" helloService)
    "systemd-generate: hello-world.service missing Description="
    (lib.throwIfNot
      (containsStr "After=network.target" helloService)
      "systemd-generate: hello-world.service missing After=network.target"
      (lib.throwIfNot
        (containsStr "ExecStart=/nix/store/" helloService)
        "systemd-generate: hello-world.service ExecStart is not a store path"
        (lib.throwIfNot
          (containsStr "Type=oneshot" helloService)
          "systemd-generate: hello-world.service missing Type=oneshot"
          # with-requires.service: direct ExecStart + Requires= from unit options
          (lib.throwIfNot
            (containsStr "ExecStart=/bin/true" withRequiresService)
            "systemd-generate: with-requires.service has wrong ExecStart"
            (lib.throwIfNot
              (containsStr "Requires=network-online.target" withRequiresService)
              "systemd-generate: with-requires.service missing Requires=network-online.target (regression of the silently-dropped-requires bug)"
              # periodic.timer: timer config rendered
              (lib.throwIfNot
                (containsStr "OnBootSec=5min" periodicTimer)
                "systemd-generate: periodic.timer missing OnBootSec"
                (lib.throwIfNot
                  (containsStr "Unit=hello-world.service" periodicTimer)
                  "systemd-generate: periodic.timer missing Unit=hello-world.service"
                  # my-target.target: Wants= gets rendered via unitConfig
                  (lib.throwIfNot
                    (containsStr "Wants=hello-world.service" myTarget)
                    "systemd-generate: my-target.target missing Wants=hello-world.service"
                    true))))))));
in
  pkgs.mkDerivation {
    pname = "systemd-generate-check";
    version = "0";
    src = null;

    # Pull the synthetic system-units derivation into the closure so it
    # gets built (and thus inspected at build time) as part of this
    # check's dependency graph.
    buildDeps = [systemUnits];

    phases = [
      {
        name = "check";
        script = ''
          set -eu
          : ${builtins.toString evalAssertions}
          echo "==> systemd-generate stage-3 check"

          units_dir="${systemUnits}"
          echo "units directory: $units_dir"

          # Every declared unit must appear as a file or symlink in the
          # generated output directory.
          for expected in \
            hello-world.service \
            with-requires.service \
            periodic.timer \
            my-target.target; do
            if [ ! -e "$units_dir/$expected" ]; then
              echo "FAIL: $expected missing from units directory"
              exit 1
            fi
          done

          # wantedBy symlinks must appear in the right .wants dirs.
          # hello-world.service + with-requires.service both declare
          # wantedBy = [ "multi-user.target" ].
          for link in \
            "multi-user.target.wants/hello-world.service" \
            "multi-user.target.wants/with-requires.service" \
            "timers.target.wants/periodic.timer"; do
            if [ ! -L "$units_dir/$link" ]; then
              echo "FAIL: expected .wants symlink $link is missing"
              exit 1
            fi
          done

          # Requires= symlink from requiredBy would go in a .requires
          # directory; we didn't use requiredBy, only `requires`, so
          # no .requires symlinks expected. `requires` generates a
          # Requires= directive in the [Unit] section (which we
          # asserted at eval time above).

          echo "==> systemd-generate stage-3 check passed."
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];

    meta.description = "Stage-3 end-to-end check for modules/systemd/system.nix";
  }
