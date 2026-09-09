##! Pure nginx aggregate provider for the checked source-composition fixture.
let
  interface = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };

  managedConfiguration =
    interface
    "aos.managed-configuration"
    "sha256:41dd1b3848c02d69542c61cdb871d588979139b321afff0edd3942c9d008fa3a";
  credentialDelivery =
    interface
    "aos.credential-delivery"
    "sha256:d282faba1d3a1afd3ed7b2cde885331d8c2cf94f9b7968eb88987cffae852a3b";
  systemdService =
    interface
    "aos.systemd-service"
    "sha256:6efc2412e7facd35f64d49b0c028517aa0fadde05d5022532455a5e70f14ced4";

  childRequest = context: scope: key: acceptedInterface: {
    id = {
      consumer = context.provider;
      inherit scope key;
    };
    accepted_interfaces = [acceptedInterface];
    methods = [];
    guarantees = [];
    lifetime = "instance";
  };

  bindingFor = context: request: let
    selected =
      builtins.filter
      (binding: binding.request == request.id)
      context.bindings;
  in
    if selected == []
    then null
    else builtins.head selected;

  lowerContribution = context: request: group: value: let
    binding = bindingFor context request;
  in
    if binding == null
    then []
    else [
      {
        request = request.id;
        aggregate = {
          provider = binding.provider;
          inherit group;
        };
        slot = context.provider.key;
        grant = binding.id;
        inherit value;
      }
    ];

  outputFrom = context: binding: sourceInterface: group: port:
    if binding == null
    then []
    else
      builtins.filter
      (output:
        output.aggregate.provider
        == binding.provider
        && output.aggregate.group == group
        && output.interface == sourceInterface
        && output.port == port)
      context.outputs;

  projectMapEntry = context: binding: sourceInterface: group: sourcePort: outputInterface: port: let
    selected = outputFrom context binding sourceInterface group sourcePort;
  in
    if
      selected
      == []
      || !builtins.hasAttr context.provider.key (builtins.head selected).value.fields
    then []
    else [
      {
        aggregate = {
          provider = context.provider;
          group = "nginx";
        };
        interface = outputInterface;
        inherit port;
        value = (builtins.head selected).value.fields.${context.provider.key};
      }
    ];

  compose = context: let
    nginx = context.interface;
    scope = [context.provider.key];
    virtualHosts =
      builtins.map
      (contribution: contribution.value)
      context.contributions;
    tlsHosts =
      builtins.filter
      (virtualHost: virtualHost.tls or false)
      virtualHosts;

    configurationRequest = childRequest context scope "configuration" managedConfiguration;
    credentialRequest = childRequest context scope "credential" credentialDelivery;
    serviceRequest = childRequest context scope "service" systemdService;
    usesTls = tlsHosts != [];
    requests =
      [configurationRequest]
      ++ (
        if usesTls
        then [credentialRequest]
        else []
      )
      ++ [serviceRequest];

    configurationBinding = bindingFor context configurationRequest;
    credentialBinding = bindingFor context credentialRequest;
    serviceBinding = bindingFor context serviceRequest;
    contributions =
      lowerContribution context configurationRequest "configuration" {
        inherit virtualHosts;
      }
      ++ (
        if usesTls
        then
          lowerContribution context credentialRequest "credentials" {
            hosts = builtins.map (virtualHost: virtualHost.host) tlsHosts;
          }
        else []
      )
      ++ lowerContribution context serviceRequest "services" {
        unit = "nginx-${context.provider.key}.service";
        virtual_host_count = builtins.length virtualHosts;
      };
  in {
    schema = "aos.ability.composition-fragment/v1";
    inherit requests contributions;
    resources = [
      {
        resource = {
          provider = context.provider;
          key = "virtual-hosts";
        };
        revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON virtualHosts)}";
      }
    ];
    outputs =
      projectMapEntry context configurationBinding managedConfiguration "configuration" "published-configurations" nginx "configuration"
      ++ projectMapEntry context credentialBinding credentialDelivery "credentials" "credential-views" nginx "credential-view"
      ++ projectMapEntry context serviceBinding systemdService "services" "managers" nginx "manager"
      ++ projectMapEntry context configurationBinding managedConfiguration "configuration" "rendered-configurations" nginx "rendered-configuration"
      ++ [
        {
          aggregate = {
            provider = context.provider;
            group = "nginx";
          };
          interface = nginx;
          port = "virtual-host-count";
          value = {
            source = "literal";
            value = builtins.length virtualHosts;
          };
        }
      ];
    controllers = [
      {
        resource = {
          provider = context.provider;
          key = "virtual-hosts";
        };
        controller = {
          provider = context.provider;
          group = "nginx";
        };
      }
    ];
  };
in {
  inherit compose;
  transition = _context: {};
}
