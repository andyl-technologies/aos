# tests/abilities/systemd-generate.nix — Stage-3 full-pipeline check.
#
# Drives `pkgs/system/_systemd-abilities/platform/system.nix` end-to-end: declare a handful of
# representative services / timers via the typed `systemd.*` options,
# evalModules with the real system.nix module, force-build the resulting
# `system.build.systemdSystemUnits` derivation, and inspect its output
# directory to assert that every expected file and symlink was produced.
#
# Complements `tests/abilities/systemd-lib.nix`, which tests the individual
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
  systemdModule = import ./_systemd-platform-module.nix;
  unselectedSystemdModule = args:
    import ../../pkgs/system/_systemd-abilities/platform/system.nix (
      args
      // {
        abilitySelection = null;
        packageArtifactFor = selector: let
          packageName =
            if selector.package == "self"
            then "systemd"
            else selector.package;
          package = pkgs.${packageName};
        in
          package.${selector.output} or package;
      }
    );
  systemdLib = import ../../pkgs/system/_systemd-abilities/platform/render.nix {inherit lib pkgs;};

  # Minimal module set: just system.nix plus a synthetic config module
  # that declares a handful of services covering the patterns we care
  # about at stage 3. Deliberately does NOT pull in the whole AOS
  # module tree — we want this check to fail in a way that points at
  # system.nix / lib.nix / unit-options.nix, not at an unrelated
  # module deep in modules/services/.
  syntheticConfig = {
    config.systemd = {
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

      # Raw-unit escape hatches exercise manifest layout cases that typed
      # services do not: an unconditional drop-in and a masked unit.
      units."upstream.service" = {
        overrideStrategy = "asDropin";
        text = ''
          [Service]
          Environment=AOS_OVERRIDE=1
        '';
      };
      units."masked.service" = {
        enable = false;
        text = null;
      };

      # A default-strategy unit without a package peer remains top-level.
      units."fresh.service".text = "[Service]\nExecStart=/bin/true\n";

      # Alias and install metadata become exact dependency links.
      units."primary.service" = {
        text = "[Service]\nExecStart=/bin/true\n";
        aliases = ["alias.service"];
      };
      units."replacement.service" = {
        text = "[Service]\nExecStart=/bin/true\n";
        wantedBy = ["multi-user.target"];
      };
    };
  };

  result = lib.evalModules {
    modules = [systemdModule syntheticConfig];
    inherit pkgs lib;
  };
  unselectedResult = lib.evalModules {
    modules = [unselectedSystemdModule];
    inherit pkgs lib;
  };

  rawTypedCrossOwnerRejected =
    !(builtins.tryEval (
      builtins.toJSON ((lib.evalModules {
          modules = [systemdModule];
          packageModules = [
            {
              name = "typed-owner";
              module.config.systemd.services.collision = {
                description = "typed";
                serviceConfig.ExecStart = "/bin/true";
              };
            }
            {
              name = "raw-owner";
              module.config.systemd.units."collision.service".text = "[Service]\nExecStart=/bin/false\n";
            }
          ];
          inherit pkgs lib;
        })
        .config
        .system
        .build
        .systemdUnitOwners)
    ))
    .success;

  baseRawTypedPackageRejected =
    !(builtins.tryEval (
      builtins.toJSON ((lib.evalModules {
          modules = [
            systemdModule
            {config.systemd.units."base-collision.service".text = "[Service]\nExecStart=/bin/false\n";}
          ];
          packageModules = [
            {
              name = "typed-owner";
              module.config.systemd.services.base-collision = {
                description = "typed";
                serviceConfig.ExecStart = "/bin/true";
              };
            }
          ];
          inherit pkgs lib;
        })
        .config
        .system
        .build
        .systemdUnitOwners)
    ))
    .success;

  pureUnits = result.config.system.build.systemdUnitBodies;
  # Standalone systemd evaluation exposes the same manifest-shaped slice that
  # the full base build binds to `system.build.configManifest`.
  manifest = result.config.system.build.systemdMaterializationData;
  systemUnits = systemdLib.materializeUnits {
    type = "system";
    inherit (manifest) etc jobScripts;
  };
  manifestSystemdEntries = lib.filterAttrs (path: _entry: lib.hasPrefix "systemd/system/" path) manifest.etc;
  expectedMaterializedPaths = builtins.map (path: lib.removePrefix "systemd/system/" path) (builtins.attrNames manifestSystemdEntries);
  expectedMaterializedPathsText = lib.concatStringsSep "\n" expectedMaterializedPaths + "\n";

  # Pull out the rendered unit texts at eval time so we can include
  # spot-checks at build time without having to grep the output dir
  # for every single assertion.
  helloService = result.config.systemd.units."hello-world.service".text;
  withRequiresService = result.config.systemd.units."with-requires.service".text;
  periodicTimer = result.config.systemd.units."periodic.timer".text;
  myTarget = result.config.systemd.units."my-target.target".text;

  containsStr = needle: haystack:
    builtins.match ".*${lib.escapeRegex needle}.*" haystack != null;

  evalChecks = [
    {
      cond =
        unselectedResult.config.system.build.systemdUnitBodies
        == {}
        && unselectedResult.config.systemd.units == {};
      msg = "systemd-generate: unselected systemd manager emitted platform configuration";
    }
    {
      cond = !lib.isDerivation pureUnits;
      msg = "systemd-generate: generateUnits output must be a pure attrset";
    }
    {
      cond = rawTypedCrossOwnerRejected && baseRawTypedPackageRejected;
      msg = "systemd-generate: raw/typed unit collisions must be rejected, including base raw definitions";
    }
    {
      cond = builtins.all (unit: builtins.isString unit.text && builtins.isString unit.mode) (builtins.attrValues pureUnits);
      msg = "systemd-generate: every pure unit must carry string text/mode fields";
    }
    {
      cond = manifest.etc."systemd/system/upstream.service.d/overrides.conf".kind == "text";
      msg = "systemd-generate: asDropin unit did not flatten to overrides.conf in the manifest";
    }
    {
      cond =
        manifest.etc."systemd/system/masked.service"
        == {
          kind = "symlink";
          target = "/dev/null";
        };
      msg = "systemd-generate: disabled unit did not flatten to a /dev/null manifest symlink";
    }
    {
      cond =
        manifest.etc."systemd/system/alias.service"
        == {
          kind = "symlink";
          target = "primary.service";
        };
      msg = "systemd-generate: generated alias did not replace package leaf";
    }
    {
      cond =
        manifest.etc."systemd/system/multi-user.target.wants/replacement.service"
        == {
          kind = "symlink";
          target = "../replacement.service";
        };
      msg = "systemd-generate: generated wantedBy did not replace package leaf";
    }
    {
      cond = containsStr "Description=Hello world stage-3 service" helloService;
      msg = "systemd-generate: hello-world.service missing Description=";
    }
    {
      cond = containsStr "After=network.target" helloService;
      msg = "systemd-generate: hello-world.service missing After=network.target";
    }
    {
      cond = containsStr "ExecStart=#aos-jobscript:" helloService;
      msg = "systemd-generate: hello-world.service ExecStart should be a job-script placeholder at eval time";
    }
    {
      cond = containsStr "Type=oneshot" helloService;
      msg = "systemd-generate: hello-world.service missing Type=oneshot";
    }
    {
      cond = containsStr "ExecStart=/bin/true" withRequiresService;
      msg = "systemd-generate: with-requires.service has wrong ExecStart";
    }
    {
      cond = containsStr "Requires=network-online.target" withRequiresService;
      msg = "systemd-generate: with-requires.service missing Requires=network-online.target";
    }
    {
      cond = containsStr "OnBootSec=5min" periodicTimer;
      msg = "systemd-generate: periodic.timer missing OnBootSec";
    }
    {
      cond = containsStr "Unit=hello-world.service" periodicTimer;
      msg = "systemd-generate: periodic.timer missing Unit=hello-world.service";
    }
    {
      cond = containsStr "Wants=hello-world.service" myTarget;
      msg = "systemd-generate: my-target.target missing Wants=hello-world.service";
    }
  ];
  evalAssertions =
    builtins.foldl' (
      ok: check:
        lib.throwIfNot check.cond check.msg ok
    )
    true
    evalChecks;
in
  pkgs.mkDerivation {
    pname = "systemd-generate-check";
    version = "0";
    src = null;

    # Pull the synthetic system-units derivation into the closure so it
    # gets built (and thus inspected at build time) as part of this
    # check's dependency graph.
    buildDeps = [systemUnits];

    expectedPaths = expectedMaterializedPathsText;
    passAsFile = ["expectedPaths"];

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
            my-target.target \
            upstream.service.d/overrides.conf \
            masked.service \
            fresh.service \
            primary.service \
            alias.service \
            replacement.service \
            multi-user.target.wants/replacement.service; do
            if [ ! -e "$units_dir/$expected" ]; then
              echo "FAIL: $expected missing from units directory"
              exit 1
            fi
          done

          # The output is assembled from configManifest.etc, so its complete
          # leaf set must match the manifest's systemd subtree, not just the
          # representative names above.
          # mkDerivation adds output metadata beside the materialized unit
          # tree. It is not part of configManifest.etc and must not enter the
          # parity comparison.
          (cd "$units_dir" && find . -path ./nix-support -prune -o \
            -mindepth 1 \( -type f -o -type l \) -print) \
            | sed 's|^\./||' | sort -u > actual-paths
          sort -u "$expectedPathsPath" > expected-paths
          if ! diff -u expected-paths actual-paths; then
            echo "FAIL: materialized systemd tree diverges from configManifest.etc"
            exit 1
          fi

          if [ "$(readlink "$units_dir/masked.service")" != "/dev/null" ]; then
            echo "FAIL: masked.service is not materialized as a /dev/null mask"
            exit 1
          fi

          if [ "$(readlink "$units_dir/alias.service")" != "primary.service" ]; then
            echo "FAIL: generated alias did not replace the package unit"
            exit 1
          fi
          if [ "$(readlink "$units_dir/multi-user.target.wants/replacement.service")" != \
               "../replacement.service" ]; then
            echo "FAIL: wantedBy link did not replace the package .wants leaf"
            exit 1
          fi

          # The eval-time unit body carries a
          # `#aos-jobscript:<key>#` placeholder, but `makeUnit` substitutes it
          # for the real job-script store path when materializing the unit
          # file. Verify the built hello-world.service has the resolved path
          # (and no leftover placeholder) so the gen-0 image is bootable.
          hw="$(cat "$units_dir/hello-world.service")"
          case "$hw" in
            *"ExecStart=/nix/store/"*) ;;
            *) echo "FAIL: built hello-world.service ExecStart is not a resolved store path"; exit 1 ;;
          esac
          case "$hw" in
            *"#aos-jobscript:"*) echo "FAIL: built hello-world.service still contains a job-script placeholder"; exit 1 ;;
            *) ;;
          esac

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

          # --- Composefs-recursion shape (spec v12 §5.2) ---
          #
          # The dump script's directory-recursion only produces a
          # correct EROFS image if `systemdSystemUnits`'s output has
          # the right shape:
          #   - The root must be a real directory (otherwise the
          #     recursion has nothing to walk).
          #   - Top-level unit files are symlinks to /nix/store
          #     (regular-file leaves → composefs symlink-to-store).
          #   - `.wants` / `.requires` / `.upholds` are real
          #     directories (subdirectory → composefs directory entry).
          #   - Install symlinks inside those dirs preserve their
          #     relative target verbatim (symlink → composefs symlink
          #     with `os.readlink`-preserved target; spec rules out
          #     `realpath` resolution).
          if [ ! -d "$units_dir" ]; then
            echo "FAIL: units_dir root is not a real directory"
            exit 1
          fi
          for top_unit in hello-world.service with-requires.service \
                          periodic.timer my-target.target; do
            if [ ! -L "$units_dir/$top_unit" ]; then
              echo "FAIL: top-level $top_unit must be a symlink (leaf-as-symlink-to-store rule)"
              exit 1
            fi
            target=$(readlink "$units_dir/$top_unit")
            case "$target" in
              /nix/store/*) ;;
              *) echo "FAIL: $top_unit symlink target is not /nix/store/* (got: $target)"; exit 1 ;;
            esac
          done
          for wants_dir in multi-user.target.wants timers.target.wants; do
            if [ ! -d "$units_dir/$wants_dir" ] || [ -L "$units_dir/$wants_dir" ]; then
              echo "FAIL: $wants_dir must be a real directory (overlayfs can't merge symlink + dir)"
              exit 1
            fi
          done
          # Install symlink target must be RELATIVE (typically
          # `../foo.service`), per generateUnits's `ln -s ../$name`
          # convention. The composefs dump script preserves this
          # verbatim via os.readlink.
          install_target=$(readlink "$units_dir/multi-user.target.wants/hello-world.service")
          case "$install_target" in
            ../hello-world.service|../hello-world.service/*) ;;
            *) echo "FAIL: install symlink target should be relative ../hello-world.service (got: $install_target)"; exit 1 ;;
          esac

          echo "==> systemd-generate stage-3 check passed."
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];

    meta.description = "Stage-3 end-to-end check for pkgs/system/_systemd-abilities/platform/system.nix";
  }
