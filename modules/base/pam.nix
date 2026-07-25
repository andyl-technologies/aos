##! modules/base/pam.nix — PAM service configuration and session env.
##!
##! Portions adapted from NixOS:
##!   nixos/modules/security/pam.nix
##!   nixos/modules/config/system-environment.nix
##!   nixos/lib/utils.nix (autoOrderRules)
##! Copyright (c) 2003-2026 Eelco Dolstra and the Nixpkgs/NixOS
##! contributors. MIT license.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.pam;
  parentConfig = config;

  autoOrderRules = rules:
    lib.pipe rules [
      (lib.imap (
        i: rule:
          if rule ? order
          then throw "autoOrderRules: 'order' may not be set on input rules"
          else rule // {order = lib.mkDefault (10000 + (i + 1) * 100);}
      ))
      (map (rule: lib.nameValuePair rule.name (removeAttrs rule ["name"])))
      lib.listToAttrs
    ];

  formatRule = type: rule:
    lib.concatStringsSep " " (
      [type rule.control rule.modulePath] ++ rule.args
    );

  formatRules = service: type:
    lib.concatStringsSep "\n" (
      map (formatRule type) (
        lib.sort (a: b: a.order < b.order) (
          lib.filter (r: r.enable) (lib.attrValues service.rules.${type})
        )
      )
    );

  renderServiceText = service:
    if service.text != null
    then service.text
    else ''
      ${formatRules service "account"}

      ${formatRules service "auth"}

      ${formatRules service "password"}

      ${formatRules service "session"}
    '';

  # The body of a pam_limits.so config file: one `<domain> <type> <item>
  # <value>` line per limit. A pure function of the limits list (no file
  # merging), so it is rendered identically at stage-1 and on-host.
  renderLimitsText = limits:
    lib.concatMapStringsSep "\n"
    (l: "${l.domain} ${l.type} ${l.item} ${toString l.value}")
    limits;

  # The merged limits.conf is registered as an image-fixed config artifact
  # keyed by a hash of its content, so identical limit sets dedupe and the
  # on-host eval-only evaluator reads a stage-1-frozen store path instead of
  # rebuilding it (`pkgs.writeTextFile` is absent from the stage-2 frozen pkgs).
  # NOTE: pam limits are operator-tunable (`aos.pam.loginLimits`), so this is a
  # *config-dependent* artifact frozen per content hash. An operator who
  # overrides limits via host.nix produces a new content hash with no frozen
  # artifact; that is a build-time rebuild today (the on-host path would fail
  # loudly rather than silently use stale limits). Full config-dependence —
  # rendering limits.conf as `/etc` data so it re-renders on-host — is tracked
  # as follow-up work in eval-only-core.md.
  limitsKey = limits: "pam-limits-" + builtins.substring 0 32 (builtins.hashString "sha256" (renderLimitsText limits));
  makeLimitsConf = limits: "${config.aos.config.artifacts.${limitsKey limits}}/limits.conf";

  defaultRules = service: {
    account = autoOrderRules [
      {
        name = "unix";
        control = "required";
        modulePath = "${pkgs.linux-pam}/lib/security/pam_unix.so";
      }
    ];
    auth = autoOrderRules [
      {
        name = "unix";
        enable = service.unixAuth;
        control = "sufficient";
        modulePath = "${pkgs.linux-pam}/lib/security/pam_unix.so";
        args =
          lib.optional service.allowNullPassword "nullok"
          ++ lib.optional service.nodelay "nodelay";
      }
      {
        name = "deny";
        control = "required";
        modulePath = "${pkgs.linux-pam}/lib/security/pam_deny.so";
      }
    ];
    password = autoOrderRules [
      {
        name = "deny";
        control = "required";
        modulePath = "${pkgs.linux-pam}/lib/security/pam_deny.so";
      }
    ];
    session = autoOrderRules [
      {
        name = "env";
        enable = service.setEnvironment;
        control = "required";
        modulePath = "${pkgs.linux-pam}/lib/security/pam_env.so";
        args = ["conffile=/etc/pam/environment" "readenv=0"];
      }
      {
        name = "unix";
        control = "required";
        modulePath = "${pkgs.linux-pam}/lib/security/pam_unix.so";
      }
      {
        name = "loginuid";
        enable = service.setLoginUid;
        control = "required";
        modulePath = "${pkgs.linux-pam}/lib/security/pam_loginuid.so";
      }
      {
        name = "limits";
        enable = service.limits != [];
        control = "required";
        modulePath = "${pkgs.linux-pam}/lib/security/pam_limits.so";
        args = ["conf=${makeLimitsConf service.limits}"];
      }
      {
        name = "systemd";
        enable = service.startSession;
        control = "optional";
        modulePath = "${pkgs.systemd}/lib/security/pam_systemd.so";
      }
    ];
  };

  ruleType = lib.types.submodule ({name, ...}: {
    options = {
      name = lib.mkOption {
        type = lib.types.str;
        readOnly = true;
        internal = true;
      };
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
      };
      order = lib.mkOption {type = lib.types.int;};
      control = lib.mkOption {type = lib.types.str;};
      modulePath = lib.mkOption {type = lib.types.str;};
      args = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
      };
    };
    config.name = name;
  });

  limitType = lib.types.submodule {
    options = {
      domain = lib.mkOption {type = lib.types.str;};
      type = lib.mkOption {type = lib.types.str;};
      item = lib.mkOption {type = lib.types.str;};
      value = lib.mkOption {
        type = lib.types.either lib.types.str lib.types.int;
      };
    };
  };

  serviceType = lib.types.submodule ({
    name,
    config,
    ...
  }: {
    options = {
      name = lib.mkOption {
        type = lib.types.str;
        default = name;
      };
      useDefaultRules = lib.mkOption {
        type = lib.types.bool;
        default = true;
      };
      unixAuth = lib.mkOption {
        type = lib.types.bool;
        default = true;
      };
      allowNullPassword = lib.mkOption {
        type = lib.types.bool;
        default = false;
      };
      nodelay = lib.mkOption {
        type = lib.types.bool;
        default = false;
      };
      setEnvironment = lib.mkOption {
        type = lib.types.bool;
        default = true;
      };
      setLoginUid = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Defaults to startSession.";
      };
      startSession = lib.mkOption {
        type = lib.types.bool;
        default = false;
      };
      limits = lib.mkOption {
        type = lib.types.listOf limitType;
        default = [];
        description = "Defaults to config.aos.pam.loginLimits.";
      };
      rules = lib.mkOption {
        type = lib.types.submodule {
          options =
            lib.genAttrs ["account" "auth" "password" "session"]
            (_:
              lib.mkOption {
                type = lib.types.attrsOf ruleType;
                default = {};
              });
        };
        default = {};
      };
      text = lib.mkOption {
        type = lib.types.nullOr lib.types.lines;
        default = null;
      };
    };
    config = {
      setLoginUid = lib.mkDefault config.startSession;
      limits = lib.mkDefault parentConfig.aos.pam.loginLimits;
      rules = lib.mkIf config.useDefaultRules (defaultRules config);
    };
  });

  formatEnvVars = vars:
    lib.concatStringsSep "\n" (
      lib.mapAttrsToList (
        n: v: let
          value =
            if builtins.isList v
            then lib.concatStringsSep ":" v
            else toString v;
        in ''${n}   DEFAULT="${value}"''
      ) (lib.filterAttrs (_: v: v != null) vars)
    );

  pamServiceFiles =
    lib.mapAttrs' (
      name: service: {
        name = "pam.d/${name}";
        value.text = renderServiceText service;
      }
    )
    cfg.services;
in {
  options.aos.pam = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to install AOS PAM configuration (per-service files
        under /etc/pam.d/ and the shared /etc/pam/environment file).
      '';
    };

    services = lib.mkOption {
      type = lib.types.attrsOf serviceType;
      default = {};
      description = ''
        Per-service PAM configuration. Each attribute name becomes a
        file at /etc/pam.d/<name>. Set `useDefaultRules = false` and
        `text = "..."` for full manual control.
      '';
    };

    loginLimits = lib.mkOption {
      type = lib.types.listOf limitType;
      default = [
        {
          domain = "*";
          type = "soft";
          item = "nofile";
          value = 65536;
        }
        {
          domain = "*";
          type = "hard";
          item = "nofile";
          value = 524288;
        }
      ];
      description = ''
        Default rlimits for login-style PAM services (sshd, login).
        Each service's `limits` defaults to this list and may be
        overridden per-service. Empty = pam_limits.so is omitted.
      '';
    };
  };

  options.environment.sessionVariables = lib.mkOption {
    type = lib.types.attrsOf (
      lib.types.either lib.types.str (lib.types.listOf lib.types.str)
    );
    default = {};
    description = ''
      Variables exported by pam_env(5) at session-open time, written
      to /etc/pam/environment in PAM key/value syntax. List values are
      joined with `:`. Note: PAM forbids `"` in values.
    '';
  };

  config = lib.mkIf cfg.enable {
    # Register every distinct non-empty limit set as an image-fixed config
    # artifact keyed by content hash. `makeLimitsConf`
    # references `artifacts.<limitsKey>` so a `pam_limits.so conf=` argument
    # resolves to the stage-1-frozen store path on-host without rebuilding.
    # Guarded so the stage-2 frozen pkgs never evaluates `writeTextFile`. The
    # drv `name` stays "pam-limits", so on a normal build this is the exact
    # same derivation as before (byte-identical).
    aos.config._artifactSources = builtins.listToAttrs (
      builtins.map (
        limits:
          lib.nameValuePair (limitsKey limits) (
            if config.aos.config.frozenArtifacts ? ${limitsKey limits}
            then null
            else
              pkgs.writeTextFile {
                name = "pam-limits";
                destination = "/limits.conf";
                text = renderLimitsText limits;
              }
          )
      ) (builtins.filter (l: l != []) (lib.mapAttrsToList (_: s: s.limits) cfg.services))
    );

    aos.pam.services.other = {
      useDefaultRules = false;
      text = ''
        account required ${pkgs.linux-pam}/lib/security/pam_warn.so
        account required ${pkgs.linux-pam}/lib/security/pam_deny.so
        auth     required ${pkgs.linux-pam}/lib/security/pam_warn.so
        auth     required ${pkgs.linux-pam}/lib/security/pam_deny.so
        password required ${pkgs.linux-pam}/lib/security/pam_warn.so
        password required ${pkgs.linux-pam}/lib/security/pam_deny.so
        session  required ${pkgs.linux-pam}/lib/security/pam_warn.so
        session  required ${pkgs.linux-pam}/lib/security/pam_deny.so
      '';
    };

    aos.pam.services.systemd-user = {
      useDefaultRules = false;
      text = ''
        account required ${pkgs.linux-pam}/lib/security/pam_unix.so no_pass_expiry
        session  required ${pkgs.linux-pam}/lib/security/pam_loginuid.so
        session  optional ${pkgs.linux-pam}/lib/security/pam_keyinit.so force revoke
        session  required ${pkgs.linux-pam}/lib/security/pam_namespace.so
        session  optional ${pkgs.linux-pam}/lib/security/pam_umask.so silent
        session  optional ${pkgs.systemd}/lib/security/pam_systemd.so
      '';
    };

    environment.sessionVariables.PATH = lib.mkDefault config.system.build.systemPath;

    environment.etc =
      pamServiceFiles
      // {
        "pam/environment".text = formatEnvVars config.environment.sessionVariables;
      };
  };
}
