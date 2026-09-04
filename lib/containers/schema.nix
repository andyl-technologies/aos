##! lib/containers/schema.nix — Typed scratch-container definition schema
##!
##! This module describes build inputs and OCI runtime metadata without
##! evaluating an AOS bootable system. The schema is deliberately closed: it
##! has no base-image, impure host-path, or secret-bearing option.
{
  config,
  lib,
  ...
}: let
  inherit (lib) mkOption types;

  # AOS's option engine delegates validation to a type's merge function. The
  # primitive types intentionally only merge, so this closed schema wraps each
  # externally writable primitive in a fail-closed merge.
  checkedType = name: base: check:
    base
    // {
      inherit name;
      check = value: base.check value && check value;
      merge = loc: definitions: let
        value = (builtins.elemAt definitions (builtins.length definitions - 1)).value;
      in
        if base.check value && check value
        then value
        else throw "The option '${lib.concatStringsSep "." loc}' is not a valid ${name}.";
    };
  validatedString = checkedType "string" types.str (_: true);
  validatedBool = checkedType "boolean" types.bool (_: true);
  package = checkedType "package" types.package (_: true);
  storePath = checkedType "Nix store path" types.pathInStore (_: true);
  positiveInt = checkedType "positive integer" types.int (value: value > 0);
  nonNegativeInt = checkedType "non-negative integer" types.int (value: value >= 0);
  absoluteContainerPath = checkedType "absolute normalized container path" types.str (value:
    builtins.match "/([^/]+(/[^/]+)*)?" value
    != null
    && builtins.match ".*(^|/)\.\.?(/|$).*" value == null);
  environmentName =
    checkedType "environment name" types.str (value:
      builtins.match "[A-Za-z_][A-Za-z0-9_]*" value != null);
  safeName =
    checkedType "lowercase name" types.str (value:
      builtins.match "[a-z0-9][a-z0-9-]*" value != null);
  repositoryName = checkedType "canonical OCI repository name" types.str (value: let
    components = lib.splitString "/" value;
    validComponent = component:
      builtins.match "[a-z0-9]+(([.]|[_][_]?|[-]+)[a-z0-9]+)*" component != null;
  in
    value
    != ""
    && builtins.stringLength value <= 255
    && builtins.all validComponent components);

  layerType = types.submodule {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = safeName;
        description = "Stable layer-family name used for reuse reporting.";
      };
      roots = mkOption {
        type = types.listOf package;
        default = [];
        description = "Package outputs whose realized closure enters this layer.";
      };
      subtractRoots = mkOption {
        type = types.listOf package;
        default = [];
        description = "Earlier cumulative roots removed from this layer's closure.";
      };
    };
  };

  directoryType = types.submodule {
    config._module.strict = true;
    options = {
      path = mkOption {
        type = absoluteContainerPath;
        description = "Absolute directory path in the scratch root.";
      };
      mode = mkOption {
        type = validatedString;
        default = "0755";
        description = "Four-digit octal directory mode.";
      };
    };
  };

  fileType = types.submodule {
    config._module.strict = true;
    options = {
      path = mkOption {
        type = absoluteContainerPath;
        description = "Absolute regular-file path in the scratch root.";
      };
      mode = mkOption {
        type = validatedString;
        default = "0644";
        description = "Four-digit octal file mode.";
      };
      text = mkOption {
        type = validatedString;
        description = "Non-secret text written verbatim to the file.";
      };
    };
  };

  facadeType = types.submodule {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = safeName;
        description = "Executable name exposed below /usr/bin.";
      };
      target = mkOption {
        type = storePath;
        description = "Absolute executable target in the Nix store.";
      };
    };
  };

  evidenceOverrideType = types.submodule {
    config._module.strict = true;
    options = {
      output = mkOption {
        type = package;
        description = "Exact generated package output receiving explicit evidence attribution.";
      };
      outputName = mkOption {
        type = safeName;
        default = "out";
        description = "Named Nix output represented by this attribution.";
      };
      pname = mkOption {
        type = safeName;
        description = "Package identity assigned by the container definition.";
      };
      version = mkOption {
        type = validatedString;
        description = "Package version assigned by the container definition.";
      };
      licenses = mkOption {
        type = types.listOf validatedString;
        description = "Reviewed license expressions covering the generated output.";
      };
      sources = mkOption {
        type = types.listOf package;
        description = "Exact source inputs retained for the generated output.";
      };
    };
  };
in {
  options = {
    name = mkOption {
      type = safeName;
      description = "Canonical local container definition name.";
    };

    packageRoots = mkOption {
      type = types.listOf package;
      description = "Exact package outputs retained as the image's baked roots.";
    };

    layers = mkOption {
      type = types.listOf layerType;
      description = "Ordered, explicitly named closure layer plan.";
    };

    filesystem = {
      files = mkOption {
        type = types.listOf fileType;
        default = [];
        description = "Additional deterministic non-secret text files in the metadata layer.";
      };
      directories = mkOption {
        type = types.listOf directoryType;
        default = [];
        description = "Additional deterministic directories in the metadata layer.";
      };
      facade = mkOption {
        type = types.listOf facadeType;
        default = [];
        description = "Explicit executable links selected ahead of the generated golden-package facade.";
      };
      allowedFacadeCollisions = mkOption {
        type = types.listOf safeName;
        default = [];
        description = "Reviewed command-name collisions allowed by the ordered golden-package facade.";
      };
      shell = mkOption {
        type = validatedBool;
        default = false;
        description = "Whether /bin/sh is exposed from the AOS bash package.";
      };
    };

    runtime = {
      entrypoint = mkOption {
        type = types.listOf validatedString;
        description = "OCI entrypoint in exec form.";
      };
      command = mkOption {
        type = types.listOf validatedString;
        default = [];
        description = "OCI default command in exec form.";
      };
      environment = mkOption {
        type = types.attrsOf validatedString;
        default = {};
        description = "Non-secret OCI environment values.";
      };
      user = mkOption {
        type = validatedString;
        default = "0:0";
        description = "Numeric OCI user and optional group.";
      };
      workingDirectory = mkOption {
        type = absoluteContainerPath;
        default = "/root";
        description = "OCI working directory.";
      };
      stopSignal = mkOption {
        type = validatedString;
        default = "SIGTERM";
        description = "Signal requested by the runtime for graceful stopping.";
      };
    };

    platform = {
      os = mkOption {
        type = types.enum ["linux"];
        default = "linux";
        description = "OCI operating system.";
      };
      architecture = mkOption {
        type = types.enum ["amd64" "arm64"];
        description = "OCI CPU architecture.";
      };
      aosSystem = mkOption {
        type = types.enum ["x86_64-linux" "aarch64-linux"];
        description = "Exact AOS target retained as an annotation.";
      };
    };

    packageManagement = {
      enable = mkOption {
        type = validatedBool;
        default = false;
        description = "Whether daemonless user-scope APM mutations are supported.";
      };
      bakedGcRoots = mkOption {
        type = validatedBool;
        default = false;
        description = "Whether init reconciles immutable roots for baked packages.";
      };
    };

    budgets = {
      maxClosureMiB = mkOption {
        type = positiveInt;
        default = 768;
        description = "Maximum total runtime closure NAR size.";
      };
      maxDevelopmentPayloadMiB = mkOption {
        type = nonNegativeInt;
        default = 48;
        description = "Maximum retained headers, static archives, and build metadata.";
      };
      maxLayers = mkOption {
        type = positiveInt;
        default = 16;
        description = "Maximum emitted layer count.";
      };
    };

    annotations = mkOption {
      type = types.attrsOf validatedString;
      default = {};
      description = "OCI annotations copied into the image manifest and index.";
    };

    publication = {
      repository = mkOption {
        type = repositoryName;
        description = "Canonical registry-local OCI repository name.";
      };
      releaseIdentity = mkOption {
        type = validatedString;
        description = "Stable signed-release identity for Hub publication.";
      };
      referenceTag = mkOption {
        type = safeName;
        default = "latest";
        description = "Mutable OCI reference included in local archives; release publication also emits an immutable version tag.";
      };
      evidenceOverrides = mkOption {
        type = types.listOf evidenceOverrideType;
        default = [];
        description = "Explicit source/license attribution for generated runtime outputs.";
      };
    };

    assertions = mkOption {
      type = types.listOf (types.submodule {
        config._module.strict = true;
        options = {
          assertion = mkOption {type = validatedBool;};
          message = mkOption {type = validatedString;};
        };
      });
      default = [];
      internal = true;
      description = "Definition invariants enforced by the evaluator.";
    };
  };

  config = {
    _module.strict = true;
    assertions = let
      layerNames = map (layer: layer.name) config.layers;
      filePaths = map (file: file.path) config.filesystem.files;
      directoryPaths = map (directory: directory.path) config.filesystem.directories;
      facadeNames = map (entry: entry.name) config.filesystem.facade;
      allowedFacadeCollisions = config.filesystem.allowedFacadeCollisions;
      environmentNames = builtins.attrNames config.runtime.environment;
      environmentValues = builtins.attrValues config.runtime.environment;
      rootPaths = map builtins.toString config.packageRoots;
      annotationKeys = builtins.attrNames config.annotations;
      annotationValues = builtins.attrValues config.annotations;
      evidenceOverridePaths = map (override: builtins.toString override.output) config.publication.evidenceOverrides;
      evidenceOverrideOutputNames = map (override: override.outputName) config.publication.evidenceOverrides;
      selectedEvidenceOverrideOutputNames =
        map
        (override: override.output.outputName or "out")
        config.publication.evidenceOverrides;
      annotationBytes =
        builtins.foldl'
        (total: value: total + builtins.stringLength value)
        0
        (annotationKeys ++ annotationValues);
    in [
      {
        assertion = config.packageRoots != [];
        message = "container baked package roots must not be empty";
      }
      {
        assertion = config.runtime.entrypoint != [];
        message = "container runtime.entrypoint must be a non-empty exec-form argument list";
      }
      {
        assertion = !config.packageManagement.enable || config.packageManagement.bakedGcRoots;
        message = "container package management requires baked GC-root reconciliation";
      }
      {
        assertion =
          config.runtime.entrypoint
          == []
          || (let
            first = builtins.head config.runtime.entrypoint;
          in
            first != "" && builtins.substring 0 1 first == "/");
        message = "container runtime.entrypoint[0] must be an absolute executable path";
      }
      {
        assertion = builtins.length config.layers <= config.budgets.maxLayers;
        message = "container layer plan exceeds budgets.maxLayers";
      }
      {
        assertion = builtins.length layerNames == builtins.length (lib.unique layerNames);
        message = "container layer names must be unique";
      }
      {
        assertion = builtins.length rootPaths == builtins.length (lib.unique rootPaths);
        message = "container baked package roots must not contain duplicate store paths";
      }
      {
        assertion = builtins.length evidenceOverridePaths == builtins.length (lib.unique evidenceOverridePaths);
        message = "container evidence overrides must name unique output paths";
      }
      {
        assertion = evidenceOverrideOutputNames == selectedEvidenceOverrideOutputNames;
        message = "container evidence override outputName must equal the selected Nix output";
      }
      {
        assertion = builtins.all (override: override.licenses != [] && override.sources != []) config.publication.evidenceOverrides;
        message = "container evidence overrides require non-empty licenses and exact source inputs";
      }
      {
        assertion = builtins.length filePaths == builtins.length (lib.unique filePaths);
        message = "container filesystem file paths must be unique";
      }
      {
        assertion = builtins.length directoryPaths == builtins.length (lib.unique directoryPaths);
        message = "container filesystem directory paths must be unique";
      }
      {
        assertion = builtins.length facadeNames == builtins.length (lib.unique facadeNames);
        message = "container executable facade names must be unique";
      }
      {
        assertion =
          builtins.all
          (file: builtins.match "[0-7][0-7][0-7][0-7]" file.mode != null)
          config.filesystem.files;
        message = "container file modes must be four-digit octal strings";
      }
      {
        assertion =
          builtins.length allowedFacadeCollisions
          == builtins.length (lib.unique allowedFacadeCollisions);
        message = "container allowed facade collision names must be unique";
      }
      {
        assertion = builtins.all environmentName.check environmentNames;
        message = "container environment names must match [A-Za-z_][A-Za-z0-9_]*";
      }
      {
        assertion =
          builtins.all
          (value:
            !lib.hasInfix "\n" value
            && !lib.hasInfix "\r" value)
          environmentValues;
        # Nix strings cannot represent NUL bytes, so only line separators need
        # an explicit evaluator guard.
        message = "container environment values must not contain line separators";
      }
      {
        assertion = builtins.all (key: builtins.stringLength key <= 1024) annotationKeys;
        message = "container annotation keys must be at most 1024 bytes";
      }
      {
        assertion = builtins.all (value: builtins.stringLength value <= 4096) annotationValues;
        message = "container annotation values must be at most 4096 bytes";
      }
      {
        assertion = annotationBytes <= 65536;
        message = "container annotations must total at most 65536 key/value bytes";
      }
      {
        assertion = builtins.match "[0-9]+(:[0-9]+)?" config.runtime.user != null;
        message = "the initial container runtime.user must be a numeric UID or UID:GID";
      }
      {
        assertion =
          builtins.all
          (directory: builtins.match "[0-7][0-7][0-7][0-7]" directory.mode != null)
          config.filesystem.directories;
        message = "container directory modes must be four-digit octal strings";
      }
    ];
  };
}
