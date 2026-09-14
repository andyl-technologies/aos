##! Canonical ability options for the AOS module fixed point.
##!
##! This module owns the shared container types only. Packages and providers
##! contribute their declarations through ordinary modules, and semantic
##! validation resolves references after the complete fixed point evaluates.
{
  mkOption,
  moduleTypes,
}: let
  strictSubmodule = options: let
    submoduleType = moduleTypes.submodule {
      _file = "<lib.abilities.module>";
      _module.strict = true;
      inherit options;
    };
  in
    submoduleType
    // {
      merge = location: definitions:
        builtins.removeAttrs (submoduleType.merge location definitions) ["_module"];
    };

  markerType = name: marker:
    moduleTypes.mkOptionType {
      inherit name;
      description = name;
      check = value: builtins.isAttrs value && (value._type or null) == marker;
      merge = moduleTypes.mergeEqualOption;
    };

  localKeyType = moduleTypes.strMatching "[A-Za-z0-9._-]+";
  qualifiedNameType = moduleTypes.strMatching "[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+";
  digestType = moduleTypes.strMatching "sha256:[0-9a-f]{64}";
  positiveU32Type =
    moduleTypes.addCheck moduleTypes.int (value:
      value > 0 && value <= 4294967295);
  stageType = moduleTypes.enum [
    "build"
    "initrd"
    "host"
    "system-container"
    "user"
    "application-container"
  ];
  lifetimeType = moduleTypes.enum [
    "attempt"
    "transaction"
    "instance"
    "persistent"
  ];

  exportType = markerType "ability implementation definition" "aos-ability-export";

  handlerType = strictSubmodule {
    artifact = mkOption {
      type = moduleTypes.nullOr moduleTypes.anything;
      default = null;
      description = "Symbolic package artifact containing the handler executable.";
    };
    entryPoint = mkOption {
      type = moduleTypes.str;
      description = "Relative executable path within the selected artifact.";
    };
    arguments = mkOption {
      type = moduleTypes.attrs;
      description = "Portable schema for the handler argument document.";
    };
    result = mkOption {
      type = moduleTypes.attrs;
      description = "Portable schema for the handler result document.";
    };
  };

  implementationType = strictSubmodule {
    definition = mkOption {
      type = exportType;
      description = "Provider-neutral interface and package-owned implementation definition.";
    };
    artifact = mkOption {
      type = moduleTypes.nullOr moduleTypes.anything;
      default = null;
      description = "Symbolic package output containing this implementation.";
    };
    artifacts = mkOption {
      type = moduleTypes.listOf moduleTypes.anything;
      default = [];
      description = "Additional symbolic package artifacts retained by this implementation.";
    };
    handler = mkOption {
      type = moduleTypes.nullOr handlerType;
      default = null;
      description = "Executable handler selected by a terminal implementation.";
    };
    requiredFeatures = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
      description = "Runtime features required to admit this implementation.";
    };
  };

  guaranteeType = strictSubmodule {
    name = mkOption {
      type = qualifiedNameType;
      description = "Provider-neutral guarantee name.";
    };
    version = mkOption {
      type = positiveU32Type;
      description = "Guarantee version.";
    };
    descriptor = mkOption {
      type = digestType;
      description = "Exact semantic guarantee descriptor.";
    };
  };

  requirementType = strictSubmodule {
    interface = mkOption {
      type = qualifiedNameType;
      description = "Provider-neutral interface name.";
    };
    abi = mkOption {
      type = positiveU32Type;
      description = "Required interface ABI.";
    };
    descriptor = mkOption {
      type = digestType;
      description = "Exact accepted interface descriptor.";
    };
    methods = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
      description = "Interface methods the consumer may invoke.";
    };
    guarantees = mkOption {
      type = moduleTypes.listOf guaranteeType;
      default = [];
      description = "Guarantees the selected implementation must provide.";
    };
    strength = mkOption {
      type = moduleTypes.enum ["required" "advisory"];
      default = "required";
      description = "Whether failure to bind prevents activation.";
    };
    fallback = mkOption {
      type = moduleTypes.nullOr moduleTypes.attrs;
      default = null;
      description = "Typed fallback outputs for an advisory requirement.";
    };
  };

  environmentType = strictSubmodule {
    authority = mkOption {
      type = localKeyType;
      description = "Authority assigning the environment identity.";
    };
    key = mkOption {
      type = localKeyType;
      description = "Stable environment key.";
    };
    stage = mkOption {
      type = stageType;
      description = "Execution stage containing the instance.";
    };
  };

  instanceIdentityType = strictSubmodule {
    environment = mkOption {
      type = environmentType;
      description = "Environment containing the instance.";
    };
    key = mkOption {
      type = localKeyType;
      description = "Stable instance key within the environment.";
    };
  };

  instanceType = strictSubmodule {
    implementation = mkOption {
      type = localKeyType;
      description = "Package implementation declaration instantiated here.";
    };
    identity = mkOption {
      type = instanceIdentityType;
      description = "Logical identity that survives package revisions.";
    };
    configuration = mkOption {
      type = moduleTypes.attrs;
      default = {};
      description = "Provider configuration checked against the interface type.";
    };
  };

  requestType = strictSubmodule {
    requirement = mkOption {
      type = localKeyType;
      description = "Package requirement template instantiated by this request.";
    };
    consumer = mkOption {
      type = instanceIdentityType;
      description = "Logical consumer instance.";
    };
    scope = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
      description = "Composition scope below the consumer.";
    };
    parameters = mkOption {
      type = moduleTypes.anything;
      description = "Request value checked against the referenced interface type.";
    };
  };

  bindingType = strictSubmodule {
    request = mkOption {
      type = localKeyType;
      description = "Concrete request selected by this binding.";
    };
    implementation = mkOption {
      type = localKeyType;
      description = "Selected package implementation declaration.";
    };
    providerInstance = mkOption {
      type = instanceIdentityType;
      description = "Selected provider instance.";
    };
    slot = mkOption {
      type = localKeyType;
      description = "Authorized aggregation slot.";
    };
  };

  desiredResourceType = strictSubmodule {
    kind = mkOption {
      type = qualifiedNameType;
      description = "Provider-neutral resource kind.";
    };
    controller = mkOption {
      type = localKeyType;
      description = "Binding that exclusively controls this resource.";
    };
    lifetime = mkOption {
      type = lifetimeType;
      description = "Retention lifetime declared by the owning interface.";
    };
    value = mkOption {
      type = moduleTypes.anything;
      description = "Desired value checked against the resource interface type.";
    };
  };
in {
  options.aos.abilities = {
    interfaces = mkOption {
      type = moduleTypes.attrsOf moduleTypes.attrs;
      default = {};
      readOnly = true;
      description = "Provider-neutral interface documents derived from implementation definitions.";
    };
    implementations = mkOption {
      type = moduleTypes.attrsOf implementationType;
      default = {};
      description = "Package-owned ability implementations available to provider discovery.";
    };
    requirementTemplates = mkOption {
      type = moduleTypes.attrsOf requirementType;
      default = {};
      description = "Package-owned ability requirements available to configured instances.";
    };
    instances = mkOption {
      type = moduleTypes.attrsOf instanceType;
      default = {};
      description = "Configured logical provider and consumer instances.";
    };
    requests = mkOption {
      type = moduleTypes.attrsOf requestType;
      default = {};
      description = "Concrete ability requests emitted by configured instances.";
    };
    bindings = mkOption {
      type = moduleTypes.attrsOf bindingType;
      default = {};
      description = "Deployment-owned exact provider selections and grants.";
    };
    desiredResources = mkOption {
      type = moduleTypes.attrsOf desiredResourceType;
      default = {};
      description = "Provider-owned desired resources derived during module evaluation.";
    };
  };
}
