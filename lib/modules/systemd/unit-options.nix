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
#   - `restartTriggers`, `reloadTriggers`, `restartIfChanged`,
#     `reloadIfChanged`, `stopIfChanged`, `notSocketActivated`, `startAt`
#     dropped (spec §5.2 / §5.3).
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
    singleton
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

  # `[Install]`-section directives. Both install models honour these
  # via the renderer in `lib.nix`'s `commonUnitText`: stage 2 ALSO
  # populates `.wants` / `.requires` / `.upholds` via `generateUnits`'s
  # symlink farm (the `[Install]` lines are idempotent for it);
  # ignition relies on these directives as the only path.
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
        - **Ignition** has no symlink-farm phase, so the renderer also
          emits an `[Install] WantedBy=` line (alongside `Alias=`,
          `RequiredBy=`, `UpheldBy=` when those fields are set). At
          first boot the initrd's `aos-ignition-preset.service` runs
          `systemctl preset-all`, which walks `[Install]` to create the
          runtime symlinks. The `[Install]` lines are idempotent for
          stage 2 (whose symlinks already exist) but load-bearing for
          ignition.
      '';
    };

    aliases = mkOption {
      default = [];
      type = types.listOf unitNameType;
      description = "Aliases of that unit.";
    };
  };

  # Stage-2-only install machinery: the `/dev/null` mask trick and the
  # auto-detected drop-in strategy. Ignition has different equivalents
  # (`mask` field, explicit `dropins[]`) which live in the ignition
  # library, not here.
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
        type = with types; coercedTo path singleton (listOf path);
        internal = true;
        description = "A list of all job script derivations of this unit.";
        default = [];
      };
    };

    # AOS adaptation (spec §5.9): script-derived `serviceConfig.Exec*`
    # assignments are wrapped in `lib.mkDefault` so user-direct
    # `ExecStart=` / etc. win silently via the module system's priority
    # mechanism. No explicit assertion is needed. Note that these rely
    # on the stage-1.5 attrsOf `dischargeProperties` change so the
    # mkDefault wrapper is resolved at the ExecStart / ExecStartPre
    # sub-attribute level inside `serviceConfig = attrsOf unitOption`.
    config = mkMerge [
      (mkIf (config.preStart != "") rec {
        jobScripts = makeJobScript {
          name = "${name}-pre-start";
          text = config.preStart;
        };
        serviceConfig.ExecStartPre = lib.mkDefault [jobScripts];
      })
      (mkIf (config.script != "") rec {
        jobScripts = makeJobScript {
          name = "${name}-start";
          text = config.script;
        };
        serviceConfig.ExecStart = lib.mkDefault (jobScripts + " " + config.scriptArgs);
      })
      (mkIf (config.postStart != "") rec {
        jobScripts = makeJobScript {
          name = "${name}-post-start";
          text = config.postStart;
        };
        serviceConfig.ExecStartPost = lib.mkDefault [jobScripts];
      })
      (mkIf (config.reload != "") rec {
        jobScripts = makeJobScript {
          name = "${name}-reload";
          text = config.reload;
        };
        serviceConfig.ExecReload = lib.mkDefault jobScripts;
      })
      (mkIf (config.preStop != "") rec {
        jobScripts = makeJobScript {
          name = "${name}-pre-stop";
          text = config.preStop;
        };
        serviceConfig.ExecStop = lib.mkDefault jobScripts;
      })
      (mkIf (config.postStop != "") rec {
        jobScripts = makeJobScript {
          name = "${name}-post-stop";
          text = config.postStop;
        };
        serviceConfig.ExecStopPost = lib.mkDefault jobScripts;
      })
    ];
  };

  stage2ServiceOptions = {
    imports = [
      stage2CommonUnitOptions
      serviceOptions
    ];
    # Upstream's `options = { restartIfChanged, reloadIfChanged,
    # stopIfChanged, notSocketActivated, startAt }` block is dropped
    # here — these are switch-to-configuration knobs (spec §5.2/§5.3).
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
