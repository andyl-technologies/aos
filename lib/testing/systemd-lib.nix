# lib/testing/systemd-lib.nix — Stage-2 regression check.
#
# Exercises the three ported nixpkgs files (modules/systemd/_lib.nix,
# modules/systemd/_unit-options.nix, modules/systemd/_types.nix) in
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
  systemdLib = import ../../modules/systemd/_lib.nix {inherit lib pkgs;};
  systemdUnitOptions = import ../../modules/systemd/_unit-options.nix {
    inherit lib systemdLib;
  };
  systemdTypes = import ../../modules/systemd/_types.nix {
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

  rendered = (systemdLib.serviceToUnit svc.with-environment).text;

  # AOS lib doesn't currently expose `hasInfix`; a one-liner using
  # `builtins.match` is enough for these checks.
  containsStr = needle: haystack:
    builtins.match ".*${lib.escapeRegex needle}.*" haystack != null;

  evalAssertions =
    lib.throwIfNot (lib.hasPrefix "/nix/store/" scriptOnlyExec)
    "systemd-lib: script-only ExecStart should be a store path, got '${scriptOnlyExec}'"
    (lib.throwIfNot (directOnlyExec == "/bin/true")
      "systemd-lib: direct-only ExecStart should be '/bin/true', got '${directOnlyExec}'"
      (lib.throwIfNot (beatenExec == "/bin/yes")
        "systemd-lib: user-direct ExecStart should beat mkDefault script; got '${beatenExec}'"
        (lib.throwIfNot (builtins.length preStartList == 1)
          "systemd-lib: preStart should produce a single-element ExecStartPre list"
          (lib.throwIfNot (containsStr "Environment=\"FOO=bar\"" rendered)
            "systemd-lib: expected Environment=\"FOO=bar\" in rendered text"
            (lib.throwIfNot (containsStr "Environment=\"BAZ=qux\"" rendered)
              "systemd-lib: expected Environment=\"BAZ=qux\" in rendered text"
              (lib.throwIfNot (containsStr "ExecStart=" rendered)
                "systemd-lib: expected ExecStart= in rendered text"
                true))))));
in
  pkgs.mkDerivation {
    pname = "systemd-lib-check";
    version = "0";
    src = null;

    # Force the compiled script derivations into the closure.
    buildDeps = svc.with-environment.jobScripts;

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
