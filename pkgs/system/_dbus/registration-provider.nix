##! Pure aggregation and configuration composition for D-Bus registrations.
{
  config,
  lib,
  packageName,
  ...
}: let
  controllerAlias = "system-registration";
  contributionAlias = "system-registration-contribution";
  controllerDeclaration = config.aos.abilities.interfaces."${packageName}:${controllerAlias}";
  aggregationSlot = controllerDeclaration.aggregation.key;
  controllerIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration controllerDeclaration
  );
  controller = config.aos.abilities.implementations."${packageName}:${controllerAlias}";
  realizationSchema =
    lib.abilities.singletonSchemaDiscriminator
    "D-Bus registration controller realization"
    controller.desiredType;
  emptyResult = {
    requests = {};
    outputs = {};
    resourceFragments = {};
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter (
      binding: binding.request == requestName
    ) (builtins.attrValues bindings);
    binding =
      if builtins.length matches == 1
      then builtins.head matches
      else throw "a D-Bus registration request must have exactly one selected binding";
  in
    if binding.slot == aggregationSlot
    then binding
    else throw "the D-Bus registration provider accepts only its canonical system-bus slot";
  entriesFor = context:
    builtins.map
    (requestName: {
      inherit requestName;
      request = context.requests.${requestName};
      binding = bindingFor context.bindings requestName;
    })
    (builtins.attrNames context.requests);
  registrationReference = instance: {
    _type = "aos-resource-reference";
    interface = controllerIdentity;
    resource = {
      provider = instance.id;
      key = aggregationSlot;
    };
    operations = ["observe"];
    lifetime = "instance";
  };
  outputsFor = instance: entries:
    builtins.listToAttrs (builtins.map (entry: {
        name = entry.requestName;
        value.resource = registrationReference instance;
      })
      entries);
  exactlyOne = description: entries:
    if builtins.length entries == 1
    then builtins.head entries
    else throw "${description} requires exactly one controller request";
  provideBase = context: let
    entry = exactlyOne "D-Bus system registration" (entriesFor context);
  in
    emptyResult
    // {
      outputs = outputsFor context.instance [entry];
      resourceFragments.${aggregationSlot} = {
        kind = controllerIdentity.name;
        lifetime = "instance";
        value = {
          base = entry.request.parameters;
          contributions = {};
        };
      };
    };
  provideContribution = context: let
    entries = entriesFor context;
    checked = builtins.map (entry:
      if entry.request.package == null
      then throw "a D-Bus registration contribution must retain its authenticated package owner"
      else entry)
    entries;
  in
    emptyResult
    // {
      outputs = outputsFor context.instance checked;
      resourceFragments = lib.optionalAttrs (checked != []) {
        ${aggregationSlot} = {
          kind = controllerIdentity.name;
          lifetime = "instance";
          value.contributions = builtins.listToAttrs (builtins.map (entry: {
              name = lib.abilities.identityKeyFor "aos.dbus.registration-contribution/v1" {
                request = entry.requestName;
              };
              value = entry.request.parameters;
            })
            checked);
        };
      };
    };
  directoryKey = reference: builtins.toJSON reference;
  uniqueDirectories = directories: let
    keys = builtins.map directoryKey directories;
  in
    builtins.length keys == builtins.length (lib.unique keys);
  literal = text: {
    kind = "literal";
    inherit text;
  };
  artifactPath = kind: reference: {
    inherit kind reference;
  };
  registrationFragments = aggregate: let
    contributions = builtins.attrValues aggregate.contributions;
    activationDirectories = builtins.concatMap (entry: entry.activation_directories) contributions;
    policyDirectories = builtins.concatMap (entry: entry.policy_directories) contributions;
    activationFragments =
      builtins.concatMap (reference: [
        (literal "  <servicedir>")
        (artifactPath "artifact-directory-path" reference)
        (literal "</servicedir>\n")
      ])
      activationDirectories;
    policyFragments =
      builtins.concatMap (reference: [
        (literal "  <includedir>")
        (artifactPath "artifact-directory-path" reference)
        (literal "</includedir>\n")
      ])
      policyDirectories;
  in
    if !uniqueDirectories activationDirectories
    then throw "D-Bus activation directory contributions collide"
    else if !uniqueDirectories policyDirectories
    then throw "D-Bus policy directory contributions collide"
    else
      [
        (literal ''
          <!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
           "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
          <busconfig>
            <include ignore_missing="no">
        '')
        (artifactPath "artifact-file-path" aggregate.base.stock_configuration)
        (literal "</include>\n")
      ]
      ++ activationFragments
      ++ policyFragments
      ++ [
        (literal "  <includedir>${aggregate.base.operator_policy_directory}</includedir>\n")
        (literal "  <include ignore_missing=\"yes\">/etc/dbus-1/system-local.conf</include>\n")
        (literal "</busconfig>\n")
      ];
  compose = {
    children,
    requests,
    resources,
    ...
  }: let
    resource = resources.${aggregationSlot} or (throw "D-Bus system registration resource is absent");
    configurationChild = children.configuration or null;
  in {
    requests.configuration = {
      requirement = "configuration-materialization";
      scope = [aggregationSlot];
      slot = aggregationSlot;
      parameters = {
        name = "dbus-system-configuration";
        source = {
          kind = "interpolated-text";
          fragments = registrationFragments resource.value;
          maximum_size_bytes = 1048576;
        };
        mode = "0444";
      };
    };
    outputs =
      if configurationChild == null
      then {}
      else
        builtins.mapAttrs (_: _: {
          configuration-path = configurationChild.outputs.planned-path.value;
          configuration-resource = configurationChild.outputs.resource.value;
        })
        requests;
    realizations.${aggregationSlot}.schema = realizationSchema;
  };
in {
  config.aos.abilities.implementations = {
    ${controllerAlias} = {
      provide = provideBase;
      inherit compose;
      transition = import ./registration-transition.nix {
        configurationInterface = lib.abilities.interfaces.serviceManagement.interfaces.managedConfiguration.identity;
        inherit (lib.abilities) transitionFragment;
      };
    };
    ${contributionAlias}.provide = provideContribution;
  };
}
