# SPDX-License-Identifier: MIT
#
# Ported from nixpkgs for use in AOS.
#   Upstream path: nixos/lib/systemd-unit-options.nix
#   Upstream rev:  6c9a78c09ff4d6c21d0319114873508a6ec01655
#
# Portions © 2003-2026 Eelco Dolstra and the Nixpkgs/NixOS contributors.
# Used under the MIT license; see nixpkgs' COPYING file for the full text.
#
# AOS adaptations (summary, spec §5):
#   - Script-derived `serviceConfig.Exec*` assignments are wrapped in
#     `lib.mkDefault` so user-direct `ExecStart`/etc. take precedence
#     without an assertion or conflict (spec §5.9).
#   - `enableStrictShellChecks` option and every `inherit (config)
#     enableStrictShellChecks;` line dropped (spec §5.4).
#   - The switch-to-configuration `X-*` contract knobs were originally
#     dropped (`restartTriggers`, `reloadTriggers`, `restartIfChanged`,
#     `reloadIfChanged`, `stopIfChanged`, `notSocketActivated`,
#     `startAt`). The live in-place `apm upgrade --system` path
#     (2026-05-27_apm_system_upgrade_refactor_v2 §6.4) restores a subset
#     as first-class options: `restartIfChanged`, `reloadIfChanged`,
#     `stopOnRemoval`, `stopOnReconfiguration`, `onlyManualStart`,
#     `notSocketActivated`, and `reloadTriggers` live on
#     `commonUnitOptions` (every unit type gets the same surface, rendered
#     into `[Unit]`); `stopIfChanged` is service-only and lives on
#     `serviceOptions`. `stopOnRemoval`, `stopOnReconfiguration`, and
#     `onlyManualStart` are new keys not present in the upstream
#     `systemd-unit-options.nix` block (upstream sets
#     `X-StopOnReconfiguration` via raw `unitConfig` on individual
#     targets). `restartTriggers` and `startAt` remain out of scope. The
#     defaults are no-ops: a default-config unit emits zero `X-*` lines,
#     so its rendered text is byte-identical to the reboot-only era.
#   - `startLimitBurst` / `startLimitIntervalSec` use `types.int` with
#     no default (matching upstream) and rely on `options.X.isDefined`
#     inside `lib.nix`'s `unitConfig` to tell whether a value was set.
#     This requires AOS's module system to thread an `options` tree
#     into submodule functions — which it now does after audit fix
#     1.2 (see `lib/modules.nix`'s `mkOptionsTree` and `evalModule`).
#   - `literalExpression` (nixpkgs doc-generation marker) is not
#     referenced — the only usage was the dropped `enableStrictShellChecks`
#     `defaultText`.
{
  lib,
  systemdLib,
}: let
  inherit
    (systemdLib)
    assertValueOneOf
    checkUnitConfig
    makeJobScript
    unitNameType
    ;

  inherit
    (lib)
    any
    concatMap
    isList
    mergeEqualOption
    mkIf
    mkMerge
    mkOption
    mkOptionType
    toList
    types
    ;

  checkService = checkUnitConfig "Service" [
    (assertValueOneOf "Type" [
      "exec"
      "simple"
      "forking"
      "oneshot"
      "dbus"
      "notify"
      "notify-reload"
      "idle"
    ])
    (assertValueOneOf "Restart" [
      "no"
      "on-success"
      "on-failure"
      "on-abnormal"
      "on-abort"
      "always"
    ])
  ];
in rec {
  unitOption = mkOptionType {
    name = "systemd option";
    merge = loc: defs:
      if any (def: isList def.value) defs
      then concatMap (def: toList def.value) defs
      else mergeEqualOption loc defs;
  };

  # Identity layer — shared by every install model.
  identityOption = {
    name = mkOption {
      type = types.str;
      description = ''
        The name of this systemd unit, including its extension.
        This can be used to refer to this unit from other systemd units.
      '';
    };
  };

  # `[Install]`-section directives. Both static and runtime package units honor
  # these via the renderer in `lib.nix`'s `commonUnitText`: stage 2 ALSO
  # populates `.wants` / `.requires` / `.upholds` via `generateUnits`'s
  # symlink farm (the `[Install]` lines are idempotent for it);
  # runtime preset policy relies on these directives as its source of truth.
  commonInstallOptions = {
    requiredBy = mkOption {
      default = [];
      type = types.listOf unitNameType;
      description = ''
        Units that require (i.e. depend on and need to go down with) this
        unit. As discussed in the `wantedBy` option description this also
        creates `.requires` symlinks automatically.
      '';
    };

    upheldBy = mkOption {
      default = [];
      type = types.listOf unitNameType;
      description = ''
        Keep this unit running as long as the listed units are running.
        This is a continuously-enforced version of wantedBy.
      '';
    };

    wantedBy = mkOption {
      default = [];
      type = types.listOf unitNameType;
      description = ''
        Units that want (i.e. depend on) this unit. The default method
        for starting a unit by default at boot time is to set this
        option to `["multi-user.target"]` for system services.

        Two install paths consume this option:

        - **Stage 2** writes a `.wants` symlink in the named target's
          `.wants/` dir at image-build time via `generateUnits` —
          stateless, no `systemctl enable` needed.
        - **Preset policy** has no symlink-farm phase, so renderers also
          emit an `[Install] WantedBy=` line (alongside `Alias=`,
          `RequiredBy=`, `UpheldBy=` when those fields are set). The
          every-boot `aos-preset.service` runs `systemctl preset-all`,
          which walks `[Install]` to create runtime symlinks in the
          tmpfs `/etc` upper. The `[Install]` lines are idempotent for
          stage 2 (whose symlinks already exist) but load-bearing for
          dynamically installed RFC-0001 package targets.
      '';
    };

    aliases = mkOption {
      default = [];
      type = types.listOf unitNameType;
      description = "Aliases of that unit.";
    };
  };

  # Stage-2 install machinery: the `/dev/null` mask trick and the
  # auto-detected drop-in strategy.
  stage2InstallOptions =
    commonInstallOptions
    // {
      enable = mkOption {
        default = true;
        type = types.bool;
        description = ''
          If set to false, this unit will be a symlink to
          /dev/null. This is primarily useful to prevent specific
          template instances (e.g. `serial-getty@ttyS0`) from being
          started. Note that `enable=true` does not make a unit start
          by default at boot; if you want that, see `wantedBy`.
        '';
      };

      overrideStrategy = mkOption {
        default = "asDropinIfExists";
        type = types.enum [
          "asDropinIfExists"
          "asDropin"
        ];
        description = ''
          Defines how unit configuration is provided for systemd:

          `asDropinIfExists` creates a unit file when no unit file is
          provided by the package; otherwise it creates a drop-in file
          named `overrides.conf`.

          `asDropin` always creates a drop-in file named `overrides.conf`.
          Needed to define instances for systemd template units
          (e.g. `systemd-nspawn@mycontainer.service`) and to enable
          upstream-provided units from `systemd.packages` (see
          `modules/base/networking.nix` for the networkd case).

          See also {manpage}`systemd.unit(5)`.
        '';
      };
    };

  # Reconstruct the legacy `sharedOptions` shape from the layered
  # halves. Stage-2 callers still see a byte-identical option surface:
  # identity + `[Install]` directives + the stage-2-only mask /
  # override-strategy fields.
  sharedOptions = identityOption // stage2InstallOptions;

  concreteUnitOptions =
    sharedOptions
    // {
      text = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Text of this systemd unit.";
      };

      unit = mkOption {
        internal = true;
        description = "The generated unit.";
      };

      # The job-script records from `makeJobScript` whose
      # `#aos-jobscript:<key>#` placeholders appear in `text`. `serviceToUnit`
      # copies the owning service's records here so `makeUnit` can substitute
      # each placeholder back to its build-side `path` when materializing the
      # bootable unit file. `text` keeps placeholders so the on-host eval-only
      # manifest (`system.build.systemdUnitBodies`) renders the unit body
      # without forcing any job-script derivation. Untyped (like `unit`) so
      # type-checking never forces the carried `path` derivations.
      jobScripts = mkOption {
        internal = true;
        default = [];
        description = "Job-script records whose placeholders appear in `text`.";
      };
    };

  commonUnitOptions = {
    options =
      sharedOptions
      // {
        description = mkOption {
          default = "";
          type = types.singleLineStr;
          description = "Description of this unit used in systemd messages and progress indicators.";
        };

        documentation = mkOption {
          default = [];
          type = types.listOf types.str;
          description = "A list of URIs referencing documentation for this unit or its configuration.";
        };

        requires = mkOption {
          default = [];
          type = types.listOf unitNameType;
          description = ''
            Start the specified units when this unit is started, and stop
            this unit when the specified units are stopped or fail.
          '';
        };

        wants = mkOption {
          default = [];
          type = types.listOf unitNameType;
          description = ''
            Start the specified units when this unit is started.
          '';
        };

        upholds = mkOption {
          default = [];
          type = types.listOf unitNameType;
          description = ''
            Keeps the specified units running while this unit is running.
            A continuous version of `wants`.
          '';
        };

        after = mkOption {
          default = [];
          type = types.listOf unitNameType;
          description = ''
            If the specified units are started at the same time as this
            unit, delay this unit until they have started.
          '';
        };

        before = mkOption {
          default = [];
          type = types.listOf unitNameType;
          description = ''
            If the specified units are started at the same time as this
            unit, delay them until this unit has started.
          '';
        };

        bindsTo = mkOption {
          default = [];
          type = types.listOf unitNameType;
          description = ''
            Like `requires`, but in addition, if the specified units
            unexpectedly disappear, this unit will be stopped as well.
          '';
        };

        partOf = mkOption {
          default = [];
          type = types.listOf unitNameType;
          description = ''
            If the specified units are stopped or restarted, then this
            unit is stopped or restarted as well.
          '';
        };

        conflicts = mkOption {
          default = [];
          type = types.listOf unitNameType;
          description = ''
            If the specified units are started, then this unit is stopped
            and vice versa.
          '';
        };

        requisite = mkOption {
          default = [];
          type = types.listOf unitNameType;
          description = ''
            Similar to requires. However if the units listed are not
            started, they will not be started and the transaction will
            fail.
          '';
        };

        unitConfig = mkOption {
          default = {};
          example = {
            RequiresMountsFor = "/data";
          };
          type = types.attrsOf unitOption;
          description = ''
            Each attribute in this set specifies an option in the
            `[Unit]` section of the unit. See {manpage}`systemd.unit(5)`
            for details.
          '';
        };

        onFailure = mkOption {
          default = [];
          type = types.listOf unitNameType;
          description = ''
            A list of one or more units that are activated when this
            unit enters the "failed" state.
          '';
        };

        onSuccess = mkOption {
          default = [];
          type = types.listOf unitNameType;
          description = ''
            A list of one or more units that are activated when this
            unit enters the "inactive" state.
          '';
        };

        startLimitBurst = mkOption {
          type = types.int;
          description = ''
            Configure unit start rate limiting. Units which are started
            more than startLimitBurst times within an interval time
            interval are not permitted to start any more.
          '';
        };

        startLimitIntervalSec = mkOption {
          type = types.int;
          description = ''
            Configure unit start rate limiting. Units which are started
            more than startLimitBurst times within an interval time
            interval are not permitted to start any more.
          '';
        };

        # ----------------------------------------------------------------
        # switch-to-configuration `X-*` contract knobs (restored, spec §6.4)
        # ----------------------------------------------------------------
        #
        # These drive the live `apm upgrade --system` reconciler. Each
        # renders an `X-*` line into the unit's `[Unit]` section (see
        # `lib.nix`'s `unitConfig` mixin), gated so the default value
        # emits nothing — a default-config unit's rendered text is
        # unchanged from before this restoration. `apm activate-reconcile`
        # reads them back to choose restart-vs-reload-vs-skip per unit.
        # They live on `commonUnitOptions` (not the service-only block, as
        # upstream does) because the shared `unitConfig` mixin reads them
        # for every unit type; `stopIfChanged` is the lone service-only
        # member and lives on `serviceOptions`.
        restartIfChanged = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Whether the unit should be restarted during a system
            configuration switch if its definition changed. When false,
            an `X-RestartIfChanged=false` marker is emitted and the
            reconciler leaves a changed unit running. `.target` units are
            never restarted directly regardless of this value — the
            reconciler's per-type policy handles them — so leaving the
            default `true` on a target is harmless (and avoids emitting a
            spurious marker on every target).
          '';
        };

        reloadIfChanged = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Whether the unit should be reloaded rather than restarted
            during a system configuration switch if its definition
            changed. Requires `ExecReload=` (or a unit type that supports
            reload); the reconciler falls back to restart with a warning
            otherwise. Prefer `reloadTriggers` for granular control.
          '';
        };

        stopOnRemoval = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Whether the unit should be stopped during a system
            configuration switch if it is removed from the new
            configuration. When false, an `X-StopOnRemoval=false` marker
            is emitted and the reconciler leaves the unit running — useful
            for units operators may have started or edited by hand.
          '';
        };

        stopOnReconfiguration = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Only meaningful on `.target` units. When true, the target is
            stopped as a dependency barrier when the units it orders have
            changed, so its dependents reconcile in the right order. Emits
            `X-StopOnReconfiguration=true`. Setting it on a non-target is
            an eval-time error.
          '';
        };

        onlyManualStart = mkOption {
          type = types.bool;
          default = false;
          description = ''
            When true, the reconciler never auto-starts this unit even if
            it is newly added to the configuration; it must be started
            manually or pulled in by another unit. Emits
            `X-OnlyManualStart=true`.
          '';
        };

        notSocketActivated = mkOption {
          type = types.bool;
          default = false;
          description = ''
            When true, a changed unit is never treated as socket-activated
            during a configuration switch, even if it has associated
            socket units: it is restarted directly rather than having its
            sockets restarted first. Emits `X-NotSocketActivated=true`.
          '';
        };

        reloadTriggers = mkOption {
          type = types.listOf types.str;
          default = [];
          example = ["/etc/sysctl.d"];
          description = ''
            A list of paths (files or directories, typically under
            `/etc`). When the content of any listed path changes between
            generations, the reconciler reloads this unit (or restarts it
            if it has no reload capability). Rendered as a space-joined
            `X-Reload-Triggers=` line. This is the AOS analogue of NixOS's
            `sysinit-reactivation.target` for the small set of in-tree
            units that re-apply `/etc` drop-ins (sysctl, modules-load,
            nftables).
          '';
        };
      };
  };

  # After the spec §5.2 cuts, stage2CommonUnitOptions has no extra options
  # beyond commonUnitOptions. Keep the name so the `types.nix` composition
  # can still say `[stage2ServiceOptions serviceConfig unitConfig
  # stage2ServiceConfig]` without modification, making future nixpkgs
  # re-syncs shallow.
  stage2CommonUnitOptions = {
    imports = [commonUnitOptions];
  };
  stage1CommonUnitOptions = commonUnitOptions;

  serviceOptions = {
    name,
    config,
    ...
  }: {
    options = {
      environment = mkOption {
        default = {};
        type = with types;
          attrsOf (
            nullOr (oneOf [
              str
              path
              package
            ])
          );
        example = {
          PATH = "/foo/bar/bin";
          LANG = "nl_NL.UTF-8";
        };
        description = "Environment variables passed to the service's processes.";
      };

      path = mkOption {
        default = [];
        type = with types;
          listOf (oneOf [
            package
            str
          ]);
        description = ''
          Packages added to the service's {env}`PATH` environment
          variable. Both the {file}`bin` and {file}`sbin` subdirectories
          of each package are added.
        '';
      };

      enableDefaultPath = mkOption {
        default = true;
        type = types.bool;
        description = ''
          Whether to append a minimal default {env}`PATH` environment
          variable to the service, containing common system utilities.
        '';
      };

      serviceConfig = mkOption {
        default = {};
        example = {
          RestartSec = 5;
        };
        type = types.addCheck (types.attrsOf unitOption) checkService;
        description = ''
          Each attribute in this set specifies an option in the
          `[Service]` section of the unit. See
          {manpage}`systemd.service(5)` for details.
        '';
      };

      script = mkOption {
        type = types.lines;
        default = "";
        description = "Shell commands executed as the service's main process.";
      };

      scriptArgs = mkOption {
        type = types.str;
        default = "";
        example = "%i";
        description = ''
          Arguments passed to the main process script. Can contain
          specifiers (`%` placeholders expanded by systemd, see
          {manpage}`systemd.unit(5)`).
        '';
      };

      preStart = mkOption {
        type = types.lines;
        default = "";
        description = ''
          Shell commands executed before the service's main process
          is started.
        '';
      };

      postStart = mkOption {
        type = types.lines;
        default = "";
        description = ''
          Shell commands executed after the service's main process
          is started.
        '';
      };

      reload = mkOption {
        type = types.lines;
        default = "";
        description = ''
          Shell commands executed when the service's main process
          is reloaded.
        '';
      };

      preStop = mkOption {
        type = types.lines;
        default = "";
        description = ''
          Shell commands executed to stop the service.
        '';
      };

      postStop = mkOption {
        type = types.lines;
        default = "";
        description = ''
          Shell commands executed after the service's main process
          has exited.
        '';
      };

      jobScripts = mkOption {
        # Each entry is the pure record returned by
        # `makeJobScript` (key/name/scriptName/text/body/mode/placeholder as
        # strings, plus `path` and the build-side `drv` derivation). The
        # records are folded into `manifest.jobScripts` and drive the
        # build-side job-script materialization. Was `listOf path` (bare
        # store paths) before the render/assemble split.
        #
        # The element type is the freeform `attrs`, NOT
        # `attrsOf (either str package)`: the latter's per-field `package`
        # check calls `isDerivation` on every record field, forcing the `drv`
        # (a `writeTextFile`) whenever the option is read — even though the
        # manifest only consumes the string fields (`key`/`body`/`mode`/
        # `scriptName`). That force faults under the on-host eval-only
        # `pkgs` (no builder functions). `attrs` validates each element is an
        # attrset without descending into (forcing) its values; `listOf`
        # still concatenates contributions across the six Exec* mkMerge blocks.
        type = with types; listOf attrs;
        internal = true;
        description = "Job-script records for this unit.";
        default = [];
      };

      # Service-only member of the `X-*` contract (spec §6.4); the other
      # seven knobs live on `commonUnitOptions`. Emitted into `[Unit]` by
      # the `serviceConfig` mixin in `lib.nix` (reading it from the shared
      # `unitConfig` mixin would fail on non-service unit types). Default
      # `true` emits nothing.
      stopIfChanged = mkOption {
        type = types.bool;
        default = true;
        description = ''
          If set, a changed service is restarted by stopping it in the old
          configuration and starting it in the new one. When false, an
          `X-StopIfChanged=false` marker is emitted and the service is
          restarted in a single `systemctl restart` step in the new
          configuration (which runs the new `ExecStop=`, so it is slightly
          less correct). Service-only; non-service unit types get their
          stop-vs-restart behaviour from the reconciler's per-type policy.
        '';
      };
    };

    # AOS adaptation (spec §5.9): script-derived `serviceConfig.Exec*`
    # assignments are wrapped in `lib.mkDefault` so user-direct
    # `ExecStart=` / etc. win silently via the module system's priority
    # mechanism. No explicit assertion is needed. Note that these rely
    # on the stage-1.5 attrsOf `dischargeProperties` change so the
    # mkDefault wrapper is resolved at the ExecStart / ExecStartPre
    # sub-attribute level inside `serviceConfig = attrsOf unitOption`.
    #
    # `makeJobScript` returns a record rather than a bare path.
    # Each block appends the record to `jobScripts` and plugs the *placeholder*
    # token (`js.placeholder = #aos-jobscript:<key>#`) into the `Exec*=`
    # directive — NOT the build-side store path. The placeholder is a pure
    # function of the unit/slot/index (no derivation), so the rendered unit
    # text is drv-free and the on-host eval-only manifest can compute it under
    # a `pkgs` that has no builder functions. The build-side
    # `makeUnit` substitutes each placeholder back to `js.path` when it
    # materializes the bootable unit file, so `system.build.systemdSystemUnits`
    # stays byte-for-byte identical. The value *shape* is unchanged (list vs.
    # string, the `script` case's `<tok> + " " + scriptArgs` form, trailing
    # space when `scriptArgs == ""`). `slot` is the systemd directive each
    # option feeds; index is always 0.
    config = mkMerge [
      (mkIf (config.preStart != "") (let
        js = makeJobScript {
          unit = "${name}.service";
          slot = "ExecStartPre";
          name = "${name}-pre-start";
          text = config.preStart;
        };
      in {
        jobScripts = [js];
        serviceConfig.ExecStartPre = lib.mkDefault [js.placeholder];
      }))
      (mkIf (config.script != "") (let
        js = makeJobScript {
          unit = "${name}.service";
          slot = "ExecStart";
          name = "${name}-start";
          text = config.script;
        };
      in {
        jobScripts = [js];
        serviceConfig.ExecStart = lib.mkDefault (js.placeholder + " " + config.scriptArgs);
      }))
      (mkIf (config.postStart != "") (let
        js = makeJobScript {
          unit = "${name}.service";
          slot = "ExecStartPost";
          name = "${name}-post-start";
          text = config.postStart;
        };
      in {
        jobScripts = [js];
        serviceConfig.ExecStartPost = lib.mkDefault [js.placeholder];
      }))
      (mkIf (config.reload != "") (let
        js = makeJobScript {
          unit = "${name}.service";
          slot = "ExecReload";
          name = "${name}-reload";
          text = config.reload;
        };
      in {
        jobScripts = [js];
        serviceConfig.ExecReload = lib.mkDefault js.placeholder;
      }))
      (mkIf (config.preStop != "") (let
        js = makeJobScript {
          unit = "${name}.service";
          slot = "ExecStop";
          name = "${name}-pre-stop";
          text = config.preStop;
        };
      in {
        jobScripts = [js];
        serviceConfig.ExecStop = lib.mkDefault js.placeholder;
      }))
      (mkIf (config.postStop != "") (let
        js = makeJobScript {
          unit = "${name}.service";
          slot = "ExecStopPost";
          name = "${name}-post-stop";
          text = config.postStop;
        };
      in {
        jobScripts = [js];
        serviceConfig.ExecStopPost = lib.mkDefault js.placeholder;
      }))
    ];
  };

  stage2ServiceOptions = {
    imports = [
      stage2CommonUnitOptions
      serviceOptions
    ];
    # Upstream declares the switch-to-configuration knobs
    # (`restartIfChanged`, `reloadIfChanged`, `stopIfChanged`,
    # `notSocketActivated`, `startAt`) in this service-only block. AOS
    # restores them for the live-upgrade contract but lifts all except
    # `stopIfChanged` up to `commonUnitOptions` (every unit type gets the
    # same `X-*` surface, rendered into `[Unit]`); see the header summary.
    # `startAt` and `restartTriggers` stay out of scope.
  };

  stage1ServiceOptions = {
    imports = [
      stage1CommonUnitOptions
      serviceOptions
    ];
  };

  socketOptions = {
    options = {
      listenStreams = mkOption {
        default = [];
        type = types.listOf types.str;
        example = [
          "0.0.0.0:993"
          "/run/my-socket"
        ];
        description = ''
          For each item in this list, a `ListenStream` option in the
          `[Socket]` section will be created.
        '';
      };

      listenDatagrams = mkOption {
        default = [];
        type = types.listOf types.str;
        example = [
          "0.0.0.0:993"
          "/run/my-socket"
        ];
        description = ''
          For each item in this list, a `ListenDatagram` option in the
          `[Socket]` section will be created.
        '';
      };

      socketConfig = mkOption {
        default = {};
        example = {
          ListenStream = "/run/my-socket";
        };
        type = types.attrsOf unitOption;
        description = ''
          Each attribute in this set specifies an option in the
          `[Socket]` section of the unit. See
          {manpage}`systemd.socket(5)` for details.
        '';
      };
    };
  };

  stage2SocketOptions = {
    imports = [
      stage2CommonUnitOptions
      socketOptions
    ];
  };
  stage1SocketOptions = {
    imports = [
      stage1CommonUnitOptions
      socketOptions
    ];
  };

  timerOptions = {
    options = {
      timerConfig = mkOption {
        default = {};
        example = {
          OnCalendar = "Sun 14:00:00";
          Unit = "foo.service";
        };
        type = types.attrsOf unitOption;
        description = ''
          Each attribute in this set specifies an option in the
          `[Timer]` section of the unit. See {manpage}`systemd.timer(5)`
          and {manpage}`systemd.time(7)` for details.
        '';
      };
    };
  };

  stage2TimerOptions = {
    imports = [
      stage2CommonUnitOptions
      timerOptions
    ];
  };
  stage1TimerOptions = {
    imports = [
      stage1CommonUnitOptions
      timerOptions
    ];
  };

  pathOptions = {
    options = {
      pathConfig = mkOption {
        default = {};
        example = {
          PathChanged = "/some/path";
          Unit = "changedpath.service";
        };
        type = types.attrsOf unitOption;
        description = ''
          Each attribute in this set specifies an option in the
          `[Path]` section of the unit. See {manpage}`systemd.path(5)`
          for details.
        '';
      };
    };
  };

  stage2PathOptions = {
    imports = [
      stage2CommonUnitOptions
      pathOptions
    ];
  };
  stage1PathOptions = {
    imports = [
      stage1CommonUnitOptions
      pathOptions
    ];
  };

  mountOptions = {
    options = {
      what = mkOption {
        example = "/dev/sda1";
        type = types.str;
        description = "Absolute path of device node, file or other resource. (Mandatory)";
      };

      where = mkOption {
        example = "/mnt";
        type = types.str;
        description = ''
          Absolute path of a directory of the mount point. Will be
          created if it doesn't exist. (Mandatory)
        '';
      };

      type = mkOption {
        default = "";
        example = "ext4";
        type = types.str;
        description = "File system type.";
      };

      options = mkOption {
        default = "";
        example = "noatime";
        type = types.commas;
        description = "Options used to mount the file system.";
      };

      mountConfig = mkOption {
        default = {};
        example = {
          DirectoryMode = "0775";
        };
        type = types.attrsOf unitOption;
        description = ''
          Each attribute in this set specifies an option in the
          `[Mount]` section of the unit. See
          {manpage}`systemd.mount(5)` for details.
        '';
      };
    };
  };

  stage2MountOptions = {
    imports = [
      stage2CommonUnitOptions
      mountOptions
    ];
  };
  stage1MountOptions = {
    imports = [
      stage1CommonUnitOptions
      mountOptions
    ];
  };

  automountOptions = {
    options = {
      where = mkOption {
        example = "/mnt";
        type = types.str;
        description = ''
          Absolute path of a directory of the mount point. Will be
          created if it doesn't exist. (Mandatory)
        '';
      };

      automountConfig = mkOption {
        default = {};
        example = {
          DirectoryMode = "0775";
        };
        type = types.attrsOf unitOption;
        description = ''
          Each attribute in this set specifies an option in the
          `[Automount]` section of the unit. See
          {manpage}`systemd.automount(5)` for details.
        '';
      };
    };
  };

  stage2AutomountOptions = {
    imports = [
      stage2CommonUnitOptions
      automountOptions
    ];
  };
  stage1AutomountOptions = {
    imports = [
      stage1CommonUnitOptions
      automountOptions
    ];
  };

  sliceOptions = {
    options = {
      sliceConfig = mkOption {
        default = {};
        example = {
          MemoryMax = "2G";
        };
        type = types.attrsOf unitOption;
        description = ''
          Each attribute in this set specifies an option in the
          `[Slice]` section of the unit. See {manpage}`systemd.slice(5)`
          for details.
        '';
      };
    };
  };

  stage2SliceOptions = {
    imports = [
      stage2CommonUnitOptions
      sliceOptions
    ];
  };
  stage1SliceOptions = {
    imports = [
      stage1CommonUnitOptions
      sliceOptions
    ];
  };
}
