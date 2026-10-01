##! Package-owned PAM service rules, limits, and session environment.
##!
##! Portions adapted from NixOS:
##!   nixos/modules/security/pam.nix
##!   nixos/modules/config/system-environment.nix
##!   nixos/lib/utils.nix (autoOrderRules)
##! Copyright (c) 2003-2026 Eelco Dolstra and the Nixpkgs/NixOS
##! contributors. MIT license.
{
  config,
  package,
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

  # Normal /etc data participates in native configuration-lower reconciliation.
  limitsKey = limits: "pam-limits-${builtins.hashString "sha256" (builtins.toJSON limits)}";
  makeLimitsConf = limits: "/etc/security/limits.d/${limitsKey limits}.conf";

  defaultRules = service: {
    account = autoOrderRules [
      {
        name = "unix";
        control = "required";
        modulePath = "${package}/lib/security/pam_unix.so";
      }
    ];
    auth = autoOrderRules [
      {
        name = "unix";
        enable = service.unixAuth;
        control = "sufficient";
        modulePath = "${package}/lib/security/pam_unix.so";
        args =
          lib.optional service.allowNullPassword "nullok"
          ++ lib.optional service.nodelay "nodelay";
      }
      {
        name = "deny";
        control = "required";
        modulePath = "${package}/lib/security/pam_deny.so";
      }
    ];
    password = autoOrderRules [
      {
        name = "deny";
        control = "required";
        modulePath = "${package}/lib/security/pam_deny.so";
      }
    ];
    session = autoOrderRules (
      [
        # Keep login keyrings private and revoke session keys at logout.
        {
          name = "keyinit";
          enable = service.startSession;
          control = "optional";
          modulePath = "${package}/lib/security/pam_keyinit.so";
          args = ["force" "revoke"];
        }
        {
          name = "env";
          enable = service.setEnvironment;
          control = "required";
          modulePath = "${package}/lib/security/pam_env.so";
          args = ["conffile=/etc/pam/environment" "readenv=0"];
        }
        {
          name = "unix";
          control = "required";
          modulePath = "${package}/lib/security/pam_unix.so";
        }
        {
          name = "loginuid";
          enable = service.setLoginUid;
          control = "required";
          modulePath = "${package}/lib/security/pam_loginuid.so";
        }
        {
          name = "limits";
          enable = service.limits != [];
          control = "required";
          modulePath = "${package}/lib/security/pam_limits.so";
          args = ["conf=${makeLimitsConf service.limits}"];
        }
      ]
      ++ lib.optional (service.startSession && cfg.sessionTrackingRule != null) ({
          name = "session-tracking";
          enable = true;
        }
        // cfg.sessionTrackingRule)
    );
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
          # SSH may supply PATH; package profiles must still take precedence.
          override = lib.optionalString (n == "PATH") " OVERRIDE=\"${value}\"";
        in ''${n}   DEFAULT="${value}"${override}''
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
    packageServices = lib.mkOption {
      type = lib.types.attrsOf lib.types.deferredModule;
      default = {};
      extensible = true;
      description = "Package-authored PAM policy merged through the same service module as operator settings.";
    };

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
    sessionTrackingRule = lib.mkOption {
      type = lib.types.nullOr (lib.types.submodule {
        options = {
          control = lib.mkOption {type = lib.types.str;};
          modulePath = lib.mkOption {type = lib.types.str;};
          args = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
          };
        };
      });
      default = null;
      internal = true;
      extensible = true;
      description = "Selected system-manager integration for authenticated login sessions.";
    };
  };

  options.aos.pam.sessionVariables = lib.mkOption {
    extensible = true;
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

  options.aos.pam.files = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule {
      options.text = lib.mkOption {
        type = lib.types.lines;
        description = "Rendered native PAM configuration file contents.";
      };
    });
    readOnly = true;
    default = {};
    description = "PAM files derived from the final merged service policy.";
  };

  config = lib.mkMerge [
    {aos.pam.services = lib.mapAttrs (_: module: {imports = [module];}) config.aos.pam.packageServices;}
    (lib.mkIf cfg.enable {
      aos.pam.services.other = {
        useDefaultRules = false;
        text = ''
          account required ${package}/lib/security/pam_warn.so
          account required ${package}/lib/security/pam_deny.so
          auth     required ${package}/lib/security/pam_warn.so
          auth     required ${package}/lib/security/pam_deny.so
          password required ${package}/lib/security/pam_warn.so
          password required ${package}/lib/security/pam_deny.so
          session  required ${package}/lib/security/pam_warn.so
          session  required ${package}/lib/security/pam_deny.so
        '';
      };

      aos.abilities.configuration.operations.file.effects = lib.mapAttrs' (path: file:
        lib.nameValuePair "pam-${builtins.hashString "sha256" path}" {
          input = {
            path = "/etc/${path}";
            content = file.text;
            mode = "0444";
          };
        })
      cfg.files;

      aos.pam.files =
        pamServiceFiles
        // builtins.listToAttrs (builtins.map (limits:
          lib.nameValuePair "security/limits.d/${limitsKey limits}.conf" {
            text = renderLimitsText limits;
          }) (builtins.filter (limits: limits != [])
          (lib.mapAttrsToList (_: service: service.limits) cfg.services)))
        // {
          "pam/environment".text = formatEnvVars cfg.sessionVariables;
        };
    })
  ];
}
