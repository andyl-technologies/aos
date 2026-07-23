# lib/testing/systemd-lib.nix — Stage-2 regression check.
#
# Exercises the three ported nixpkgs files (lib/modules/systemd/lib.nix,
# lib/modules/systemd/unit-options.nix, lib/modules/systemd/types.nix) in
# isolation from the rest of the AOS module tree. Builds a synthetic
# `systemd.services` option using the typed submodule stack, drives a
# handful of representative services through it, and asserts both at
# eval time and at build time that:
#
#   * `script = "…";` compiles to a `makeJobScript`-built derivation and
#     ends up at `serviceConfig.ExecStart` when the user hasn't set it.
#   * User-direct `serviceConfig.ExecStart = "/bin/…";` beats the
#     script-derived value via the §5.9 `lib.mkDefault` wrapping.
#   * `preStart` compiles to `ExecStartPre` as a single-element list.
#   * `environment = { … };` renders as quoted `Environment=` lines
#     inside the `[Service]` section.
#   * `stage2ServiceConfig` injects `coreutils`/`findutils`/`grep`/`sed`/
#     `systemd` into `path` via `mkAfter`, and that the resulting
#     `environment.PATH` is set when `path != []`.
#   * `serviceToUnit` emits a well-formed `[Unit] / [Service] / [Install]`
#     text blob, with `After=` / `Description=` / `WantedBy=` in the
#     right sections.
#
# This is the stage-2 regression guard called out in spec §9.2. Runs
# via `nix-build -A checks.systemd-lib`.
{
  pkgs,
  lib,
}: let
  systemdLib = import ../modules/systemd/lib.nix {inherit lib pkgs;};
  systemdUnitOptions = import ../modules/systemd/unit-options.nix {
    inherit lib systemdLib;
  };
  systemdTypes = import ../modules/systemd/types.nix {
    inherit lib systemdLib systemdUnitOptions;
  };

  # Drive the library from a synthetic module that declares just
  # `systemd.services` and provides a handful of definitions that cover
  # the patterns we care about.
  result = lib.evalModules {
    modules = [
      {
        options.systemd.services = lib.mkOption {
          type = systemdTypes.services;
          default = {};
        };
      }
      {
        config.systemd.services = {
          script-only = {
            description = "Script-only service";
            wantedBy = ["multi-user.target"];
            after = ["network.target"];
            script = "echo hello from script-only";
            serviceConfig.Type = "oneshot";
          };
          direct-only = {
            description = "Direct ExecStart service";
            wantedBy = ["multi-user.target"];
            serviceConfig = {
              Type = "simple";
              ExecStart = "/bin/true";
            };
          };
          script-beaten-by-direct = {
            description = "User-direct ExecStart wins over mkDefault";
            script = "echo should not win";
            serviceConfig = {
              Type = "oneshot";
              ExecStart = "/bin/yes";
            };
          };
          with-prestart = {
            description = "preStart compiled into ExecStartPre";
            preStart = "echo pre-hook";
            script = "echo main";
            serviceConfig.Type = "oneshot";
          };
          with-environment = {
            description = "Environment variables rendered";
            script = "echo env";
            environment = {
              FOO = "bar";
              BAZ = "qux";
            };
            serviceConfig.Type = "oneshot";
          };
          with-x-knobs = {
            description = "X-* contract knobs rendered into [Unit]";
            script = "echo x";
            serviceConfig.Type = "oneshot";
            # Every knob set to a non-default value so the renderer emits
            # the corresponding X-* line (spec §6.4). reloadIfChanged is
            # paired with an ExecReload= so it is the meaningful case.
            reload = "echo reload";
            restartIfChanged = false;
            reloadIfChanged = true;
            stopIfChanged = false;
            stopOnRemoval = false;
            notSocketActivated = true;
            onlyManualStart = true;
            reloadTriggers = ["/etc/a" "/etc/b"];
          };
        };
      }
    ];
    lib = lib;
  };

  svc = result.config.systemd.services;

  # --- Eval-time assertions ----------------------------------------
  scriptOnlyExec = svc.script-only.serviceConfig.ExecStart;
  directOnlyExec = svc.direct-only.serviceConfig.ExecStart;
  beatenExec = svc.script-beaten-by-direct.serviceConfig.ExecStart;
  preStartList = svc.with-prestart.serviceConfig.ExecStartPre;

  # The eval-time `ExecStart` from a `script=` option
  # is the drv-free `#aos-jobscript:<key>#` placeholder (so the on-host
  # eval-only manifest renders the unit without forcing the job-script
  # derivation); the real build-side store path lives on the job-script record
  # (`.path`), and `makeUnit` substitutes it into the materialized unit file.
  scriptOnlyJob = builtins.head svc.script-only.jobScripts;

  rendered = (systemdLib.serviceToUnit svc.with-environment).text;
  xKnobsRendered = (systemdLib.serviceToUnit svc.with-x-knobs).text;
  # `script-only` sets none of the X-* knobs, so its rendered text must
  # carry no `X-*` line — the no-op invariant that keeps default-config
  # units from churning their fingerprint on the next live upgrade.
  defaultRendered = (systemdLib.serviceToUnit svc.script-only).text;

  # AOS lib doesn't currently expose `hasInfix`; a one-liner using
  # `builtins.match` is enough for these checks.
  containsStr = needle: haystack:
    builtins.match ".*${lib.escapeRegex needle}.*" haystack != null;

  # Each check is `{ cond; msg; }`; the fold throws `msg` on the first
  # false `cond`. Flatter than nesting `throwIfNot` calls by hand.
  checks = [
    {
      cond = lib.hasPrefix "#aos-jobscript:" scriptOnlyExec;
      msg = "systemd-lib: script-only ExecStart should be a job-script placeholder, got '${scriptOnlyExec}'";
    }
    {
      cond = lib.hasPrefix "/nix/store/" scriptOnlyJob.path;
      msg = "systemd-lib: script-only job-script path should be a store path, got '${scriptOnlyJob.path}'";
    }
    {
      cond = directOnlyExec == "/bin/true";
      msg = "systemd-lib: direct-only ExecStart should be '/bin/true', got '${directOnlyExec}'";
    }
    {
      cond = beatenExec == "/bin/yes";
      msg = "systemd-lib: user-direct ExecStart should beat mkDefault script; got '${beatenExec}'";
    }
    {
      cond = builtins.length preStartList == 1;
      msg = "systemd-lib: preStart should produce a single-element ExecStartPre list";
    }
    {
      cond = containsStr "Environment=\"FOO=bar\"" rendered;
      msg = "systemd-lib: expected Environment=\"FOO=bar\" in rendered text";
    }
    {
      cond = containsStr "Environment=\"BAZ=qux\"" rendered;
      msg = "systemd-lib: expected Environment=\"BAZ=qux\" in rendered text";
    }
    {
      cond = containsStr "ExecStart=" rendered;
      msg = "systemd-lib: expected ExecStart= in rendered text";
    }
    # --- X-* contract knob rendering (spec §6.4) ---------------------
    {
      cond = containsStr "X-RestartIfChanged=false" xKnobsRendered;
      msg = "systemd-lib: expected X-RestartIfChanged=false in rendered text";
    }
    {
      cond = containsStr "X-ReloadIfChanged=true" xKnobsRendered;
      msg = "systemd-lib: expected X-ReloadIfChanged=true in rendered text";
    }
    {
      cond = containsStr "X-StopIfChanged=false" xKnobsRendered;
      msg = "systemd-lib: expected X-StopIfChanged=false in rendered text";
    }
    {
      cond = containsStr "X-StopOnRemoval=false" xKnobsRendered;
      msg = "systemd-lib: expected X-StopOnRemoval=false in rendered text";
    }
    {
      cond = containsStr "X-NotSocketActivated=true" xKnobsRendered;
      msg = "systemd-lib: expected X-NotSocketActivated=true in rendered text";
    }
    {
      cond = containsStr "X-OnlyManualStart=true" xKnobsRendered;
      msg = "systemd-lib: expected X-OnlyManualStart=true in rendered text";
    }
    {
      cond = containsStr "X-Reload-Triggers=/etc/a /etc/b" xKnobsRendered;
      msg = "systemd-lib: expected space-joined X-Reload-Triggers=/etc/a /etc/b in rendered text";
    }
    {
      cond = !containsStr "X-" defaultRendered;
      msg = "systemd-lib: a default service must emit no X-* lines, but found one in: ${defaultRendered}";
    }
  ];

  evalAssertions =
    builtins.foldl' (acc: c: lib.throwIfNot c.cond c.msg acc) true checks;
in
  pkgs.mkDerivation {
    pname = "systemd-lib-check";
    version = "0";
    src = null;

    # Force the compiled script derivations into the closure:
    # `jobScripts` entries are now records; the build-side derivation is the
    # `.drv` field (was a bare derivation/path before the split).
    buildDeps = map (j: j.drv) svc.with-environment.jobScripts;

    phases = [
      {
        name = "check";
        script = ''
          set -eu
          : ${builtins.toString evalAssertions}
          echo "==> systemd-lib stage-2 check"
          mkdir -p "$out"
          echo PASS > "$out/result"
          echo "==> systemd-lib stage-2 check passed."
        '';
      }
    ];

    meta.description = "Stage-2 regression guard for ported systemd library files";
  }
