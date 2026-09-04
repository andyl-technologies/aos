# lib/testing/systemd-generate.nix — Stage-3 full-pipeline check.
#
# Drives `modules/systemd/system.nix` end-to-end: declare a handful of
# representative services / timers via the typed `systemd.*` options,
# evalModules with the real system.nix module, force-build the resulting
# `system.build.systemdSystemUnits` derivation, and inspect its output
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
  systemdLib = import ../modules/systemd/lib.nix {inherit lib pkgs;};

  # A package-shaped fixture with the same mixture the historical imperative
  # generateUnits walker handled: plain units, a source symlink, a drop-in,
  # and a pre-existing .wants link. The inventory is authored as derivation
  # metadata, so evaluating the system manifest never reads this output.
  packagedUnits =
    pkgs.runCommand "systemd-package-inventory-fixture" {
      passthru.systemdUnitInventory.system = [
        "lib/systemd/system/vendor.service"
        "lib/systemd/system/linked.service"
        "lib/systemd/system/vendor.service.d/10-vendor.conf"
        "lib/systemd/system/multi-user.target.wants/linked.service"
        "lib/systemd/system/alias.service"
        "lib/systemd/system/multi-user.target.wants/replacement.service"
      ];
    } ''
      mkdir -p \
        "$out/lib/systemd/system/vendor.service.d" \
        "$out/lib/systemd/system/multi-user.target.wants"
      printf '%s\n' '[Unit]' 'Description=Vendor unit' '[Service]' 'ExecStart=/bin/true' \
        > "$out/lib/systemd/system/vendor.service"
      ln -s vendor.service "$out/lib/systemd/system/linked.service"
      printf '%s\n' '[Service]' 'Environment=VENDOR_DROPIN=1' \
        > "$out/lib/systemd/system/vendor.service.d/10-vendor.conf"
      ln -s ../linked.service \
        "$out/lib/systemd/system/multi-user.target.wants/linked.service"
      printf '%s\n' '[Service]' 'ExecStart=/bin/false' \
        > "$out/lib/systemd/system/alias.service"
      ln -s ../linked.service \
        "$out/lib/systemd/system/multi-user.target.wants/replacement.service"
    '';

  # Minimal module set: just system.nix plus a synthetic config module
  # that declares a handful of services covering the patterns we care
  # about at stage 3. Deliberately does NOT pull in the whole AOS
  # module tree — we want this check to fail in a way that points at
  # system.nix / lib.nix / unit-options.nix, not at an unrelated
  # module deep in modules/services/.
  syntheticConfig = {
    config.systemd = {
      packages = [packagedUnits];

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

      # The package already provides this name, so the default
      # asDropinIfExists strategy must preserve the package unit and render the
      # authored text as overrides.conf.
      units."vendor.service".text = ''
        [Service]
        Environment=AOS_OVERRIDE=1
      '';

      # A default-strategy unit without a package peer remains top-level.
      units."fresh.service".text = "[Service]\nExecStart=/bin/true\n";

      # Historical alias/install ln -sfn operations replace package leaves at
      # the exact same final path.
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

  rawTypedCrossOwnerRejected =
    !(builtins.tryEval (
      builtins.toJSON ((lib.evalModules {
          modules = [systemdModule];
          packageModules = [
            {
              name = "typed-owner";
              authorization = {
                owns = ["systemd"];
                contributes = {};
              };
              module.config.systemd.services.collision = {
                description = "typed";
                serviceConfig.ExecStart = "/bin/true";
              };
            }
            {
              name = "raw-owner";
              authorization = {
                owns = ["systemd"];
                contributes = {};
              };
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
              authorization = {
                owns = ["systemd"];
                contributes = {};
              };
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

  systemUnits = result.config.system.build.systemdSystemUnits;
  pureUnits = result.config.system.build.systemdUnitBodies;
  # Standalone systemd evaluation exposes the same manifest-shaped slice that
  # the full base build binds to `system.build.configManifest`.
  manifest = result.config.system.build.systemdMaterializationData;
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
        manifest.etc."systemd/system/vendor.service"
        == {
          kind = "symlink";
          target = "${packagedUnits}/lib/systemd/system/vendor.service";
        };
      msg = "systemd-generate: package unit was not preserved by asDropinIfExists";
    }
    {
      cond = manifest.etc."systemd/system/vendor.service.d/overrides.conf".kind == "text";
      msg = "systemd-generate: asDropinIfExists did not render overrides.conf";
    }
    {
      cond =
        manifest.etc."systemd/system/vendor.service.d/10-vendor.conf"
        == {
          kind = "symlink";
          target = "${packagedUnits}/lib/systemd/system/vendor.service.d/10-vendor.conf";
        };
      msg = "systemd-generate: package drop-in was not merged";
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

  # Adversarial parity oracle: reconstruct the pre-split imperative symlink
  # farm for this same evaluated unit set. The final check canonicalizes
  # absolute store links by their target bytes (the pure materializer may use
  # a differently named one-file derivation) while retaining relative link
  # targets verbatim. This pins the historical package merge semantics rather
  # than merely checking a few expected filenames.
  legacyUnitDrvs =
    lib.mapAttrs (
      name: unit:
        systemdLib.makeUnit name unit
    )
    result.config.systemd.units;
  autoUnitDrvs = lib.mapAttrsToList (name: _unit: legacyUnitDrvs.${name}) (
    lib.filterAttrs (
      _name: unit:
        (unit.overrideStrategy or "asDropinIfExists") == "asDropinIfExists"
    )
    result.config.systemd.units
  );
  dropinUnitDrvs = lib.mapAttrsToList (name: _unit: legacyUnitDrvs.${name}) (
    lib.filterAttrs (
      _name: unit:
        (unit.overrideStrategy or "asDropinIfExists") == "asDropin"
    )
    result.config.systemd.units
  );
  legacyUnits = pkgs.runCommand "legacy-system-units-parity-oracle" {} ''
    mkdir -p "$out"

    unit_filename() {
      unit_dir=$1
      unit_filename=
      for candidate in "$unit_dir"/*; do
        [ -e "$candidate" ] || [ -L "$candidate" ] || continue
        [ -d "$candidate" ] && continue
        if [ -n "$unit_filename" ]; then
          echo "unit derivation contains multiple unit payloads: $unit_dir" >&2
          exit 1
        fi
        unit_filename=$(basename "$candidate")
      done
      if [ -z "$unit_filename" ]; then
        echo "unit derivation contains no unit payload: $unit_dir" >&2
        exit 1
      fi
    }

    for base in \
      "${packagedUnits}/etc/systemd/system" \
      "${packagedUnits}/lib/systemd/system"; do
      [ -d "$base" ] || continue
      for fn in "$base"/*; do
        [ -e "$fn" ] || continue
        bn=$(basename "$fn")
        if [ -d "$fn" ]; then
          mkdir -p "$out/$bn"
          for inner in "$fn"/*; do
            [ -e "$inner" ] || continue
            ln -s "$inner" "$out/$bn/$(basename "$inner")"
          done
        else
          ln -s "$fn" "$out/$bn"
        fi
      done
    done

    for unit_dir in ${builtins.toString autoUnitDrvs}; do
      unit_filename "$unit_dir"
      fn=$unit_filename
      if [ -e "$out/$fn" ]; then
        if [ "$(readlink -f "$unit_dir/$fn")" = /dev/null ]; then
          ln -sfn /dev/null "$out/$fn"
        else
          mkdir -p "$out/$fn.d"
          ln -s "$unit_dir/$fn" "$out/$fn.d/overrides.conf"
        fi
      else
        ln -fs "$unit_dir/$fn" "$out/"
      fi
    done

    for unit_dir in ${builtins.toString dropinUnitDrvs}; do
      unit_filename "$unit_dir"
      fn=$unit_filename
      mkdir -p "$out/$fn.d"
      ln -s "$unit_dir/$fn" "$out/$fn.d/overrides.conf"
    done

    ${lib.concatStrings (lib.mapAttrsToList (
        name: unit:
          lib.concatMapStrings (alias: ''
            ln -sfn ${lib.escapeShellArg name} "$out/${alias}"
          '') (unit.aliases or [])
      )
      result.config.systemd.units)}
    ${lib.concatStrings (lib.mapAttrsToList (
        name: unit:
          lib.concatMapStrings (target: ''
            mkdir -p "$out/${target}.wants"
            ln -sfn ${lib.escapeShellArg "../${name}"} "$out/${target}.wants/"
          '') (unit.wantedBy or [])
      )
      result.config.systemd.units)}
    ${lib.concatStrings (lib.mapAttrsToList (
        name: unit:
          lib.concatMapStrings (target: ''
            mkdir -p "$out/${target}.requires"
            ln -sfn ${lib.escapeShellArg "../${name}"} "$out/${target}.requires/"
          '') (unit.requiredBy or [])
      )
      result.config.systemd.units)}
    ${lib.concatStrings (lib.mapAttrsToList (
        name: unit:
          lib.concatMapStrings (target: ''
            mkdir -p "$out/${target}.upholds"
            ln -sfn ${lib.escapeShellArg "../${name}"} "$out/${target}.upholds/"
          '') (unit.upheldBy or [])
      )
      result.config.systemd.units)}
  '';
in
  pkgs.mkDerivation {
    pname = "systemd-generate-check";
    version = "0";
    src = null;

    # Pull the synthetic system-units derivation into the closure so it
    # gets built (and thus inspected at build time) as part of this
    # check's dependency graph.
    buildDeps = [systemUnits legacyUnits pkgs.python3];

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
            vendor.service \
            vendor.service.d/10-vendor.conf \
            vendor.service.d/overrides.conf \
            linked.service \
            multi-user.target.wants/linked.service \
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

          # Package leaves retain the historical symlink-to-package shape,
          # including a package source that is itself a symlink. Drop-ins merge
          # rather than shadowing the package-provided directory.
          if [ "$(readlink "$units_dir/vendor.service")" != \
               "${packagedUnits}/lib/systemd/system/vendor.service" ]; then
            echo "FAIL: vendor.service does not point at the package leaf"
            exit 1
          fi
          if [ "$(readlink "$units_dir/linked.service")" != \
               "${packagedUnits}/lib/systemd/system/linked.service" ]; then
            echo "FAIL: linked.service did not preserve the package source symlink boundary"
            exit 1
          fi
          if ! grep -Fq 'Environment=VENDOR_DROPIN=1' \
               "$units_dir/vendor.service.d/10-vendor.conf"; then
            echo "FAIL: package drop-in bytes changed"
            exit 1
          fi
          if ! grep -Fq 'Environment=AOS_OVERRIDE=1' \
               "$units_dir/vendor.service.d/overrides.conf"; then
            echo "FAIL: asDropinIfExists override bytes changed"
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

          # Compare the complete pre/post tree. Absolute store links are
          # represented by the bytes and mode of the leaf they resolve to;
          # relative install/alias links remain exact link-target strings.
          ${pkgs.python3}/bin/python3 - "${legacyUnits}" "$units_dir" <<'PY'
          import hashlib
          import json
          import os
          import stat
          import sys

          def canonical(root):
              result = {}
              for base, dirs, files in os.walk(root, followlinks=False):
                  dirs.sort()
                  files.sort()
                  for name in files:
                      path = os.path.join(base, name)
                      relative = os.path.relpath(path, root)
                      if os.path.islink(path):
                          target = os.readlink(path)
                          resolved = os.path.realpath(path)
                          if resolved == "/dev/null":
                              result[relative] = ["mask"]
                          elif os.path.isabs(target):
                              with open(path, "rb") as source:
                                  digest = hashlib.sha256(source.read()).hexdigest()
                              result[relative] = ["content", stat.S_IMODE(os.stat(path).st_mode), digest]
                          else:
                              result[relative] = ["link", target]
                      else:
                          with open(path, "rb") as source:
                              digest = hashlib.sha256(source.read()).hexdigest()
                          result[relative] = ["content", stat.S_IMODE(os.stat(path).st_mode), digest]
              return result

          before = canonical(sys.argv[1])
          after = canonical(sys.argv[2])
          if before != after:
              print("FAIL: pure systemd materialization changed legacy bytes or symlink semantics")
              print(json.dumps({"legacy": before, "pure": after}, indent=2, sort_keys=True))
              raise SystemExit(1)
          PY

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

    meta.description = "Stage-3 end-to-end check for modules/systemd/system.nix";
  }
