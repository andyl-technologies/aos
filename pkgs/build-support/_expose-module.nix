##! pkgs/build-support/_expose-module.nix - typed package expose surface.
##!
##! This module is the schema boundary shared by the legacy expose renderer and
##! config-module migration checks.  It deliberately models the package-authored
##! surface, before `_expose-renderer.nix` synthesizes side-effect units.  The
##! renderer retains its semantic validation (path confinement, unit references,
##! credential combinations, and privilege policy); this layer makes every
##! public expose family a real `mkOption` so malformed values fail in the same
##! module engine used by on-host evaluation.
{lib}: let
  inherit (lib) mkOption types;

  strict = options: {
    inherit options;
    config._module.strict = true;
  };

  # AOS's option types expose `check`, but primitive/list merges intentionally
  # assume their input shape.  Wrap them at this trust boundary so a bad type
  # becomes a catchable module error instead of leaking a low-level builtin
  # type fault from `map`/`attrNames`.
  checked = type:
    type
    // {
      merge = loc: defs:
        if builtins.all (definition: type.check definition.value) defs
        then type.merge loc defs
        else throw "The option '${builtins.concatStringsSep "." loc}' must be ${type.description}.";
    };
  string = checked types.str;
  boolean = checked types.bool;
  integer = checked types.int;
  attrs = checked types.attrs;
  nullable = type: checked (types.nullOr type);
  listOf = type: checked (types.listOf type);
  attrsOf = type: checked (types.attrsOf type);
  oneOf = left: right: checked (types.either left right);
  enum = values: checked (types.enum values);
  submodule = module: checked (types.submodule module);
  stringList = listOf string;
  portList = listOf integer;

  firewallType = submodule (strict {
    allowedTCP = mkOption {
      type = portList;
      default = [];
    };
    allowedUDP = mkOption {
      type = portList;
      default = [];
    };
    forwardPolicy = mkOption {
      type = enum ["drop" "accept"];
      default = "drop";
    };
  });

  kernelType = submodule (strict {
    modules = mkOption {
      type = stringList;
      default = [];
    };
    sysctl = mkOption {
      type = attrsOf (oneOf string integer);
      default = {};
    };
  });

  artifactType = submodule (strict {
    name = mkOption {type = string;};
    path = mkOption {type = string;};
    format = mkOption {
      type = enum ["env" "json" "toml"];
      default = "env";
    };
    required = mkOption {
      type = stringList;
      default = [];
    };
    optional = mkOption {
      type = stringList;
      default = [];
    };
    units = mkOption {
      type = stringList;
      default = [];
    };
    reload = mkOption {
      type = enum ["restart" "reload" "none"];
      default = "restart";
    };
  });

  # `encryptedFile` accepts a path or a store-path string.  The companion
  # output's reference/literal scan and the expose renderer's store-path check
  # remain the authority for its provenance.
  credentialType = submodule (strict {
    name = mkOption {type = string;};
    source = mkOption {
      type = nullable string;
      default = null;
    };
    ciphertext = mkOption {
      type = nullable string;
      default = null;
    };
    units = mkOption {
      type = stringList;
      default = [];
    };
    encrypted = mkOption {
      type = boolean;
      default = false;
    };
    optional = mkOption {
      type = boolean;
      default = false;
    };
    encryptedFile = mkOption {
      type = nullable (oneOf (checked types.path) string);
      default = null;
    };
  });

  configType = submodule (strict {
    artifacts = mkOption {
      type = listOf artifactType;
      default = [];
    };
    credentials = mkOption {
      type = listOf credentialType;
      default = [];
    };
  });

  hostPathType = submodule (strict {
    path = mkOption {type = string;};
    mode = mkOption {type = enum ["read-only" "rw"];};
  });

  permissionsType = submodule (strict {
    capabilities = mkOption {
      type = stringList;
      default = [];
    };
    network = mkOption {
      type = nullable (enum ["private" "private-outbound" "host"]);
      default = null;
    };
    "tcp-bind" = mkOption {
      type = portList;
      default = [];
    };
    "tcp-connect" = mkOption {
      type = portList;
      default = [];
    };
    devices = mkOption {
      type = stringList;
      default = [];
    };
    "host-paths" = mkOption {
      type = listOf hostPathType;
      default = [];
    };
    "cgroup-delegate" = mkOption {
      type = boolean;
      default = false;
    };
    "privileged-users" = mkOption {
      type = boolean;
      default = false;
    };
    "kernel-modules" = mkOption {
      type = stringList;
      default = [];
    };
    syscalls = mkOption {
      type = nullable (enum ["restricted" "system-service" "privileged"]);
      default = null;
    };
    "security-label" = mkOption {
      type = nullable string;
      default = null;
    };
  });

  exposeOptions = {
    target = mkOption {
      type = nullable string;
      default = null;
    };
    # The unit's suffix selects the concrete systemd submodule.  The legacy
    # renderer evaluates those concrete typed submodules after synthesizing
    # its security and side-effect fields.
    units = mkOption {
      type = attrsOf attrs;
      default = {};
    };
    kernel = mkOption {
      type = kernelType;
      default = {};
    };
    firewall = mkOption {
      type = firewallType;
      default = {};
    };
    images = mkOption {
      type = listOf attrs;
      default = [];
    };
    permissions = mkOption {
      type = permissionsType;
      default = {};
    };
    config = mkOption {
      type = configType;
      default = {};
    };
    provides = mkOption {
      type = listOf attrs;
      default = [];
    };
    uses = mkOption {
      type = listOf attrs;
      default = [];
    };
    prepareHostPathDirectories = mkOption {
      type = stringList;
      default = [];
    };
  };
in {
  inherit exposeOptions;

  ## Evaluates one authored expose value through the module system.
  ##
  ## The returned value has typed defaults populated.  Semantic validation is
  ## intentionally performed by `_expose-renderer.nix` immediately afterwards.
  eval = expose:
    (lib.evalModules {
      modules = [
        {
          options.packageExpose = exposeOptions;
          config = {
            _module.strict = true;
            packageExpose = expose;
          };
        }
      ];
      inherit lib;
    })
    .config
    .packageExpose;
}
