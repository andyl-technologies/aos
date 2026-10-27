##! Checks fixed initial-floor installation through the actual server modules.
##!
##! Incomplete selections must fail configuration admission. A later positive
##! caller supplies actual image policy, Parent06 subdivisions and external
##! credential names; this check invents no Source, approval or TPM authority.
{
  lib,
  mkSystem,
}: let
  purposes = ["controller" "storage"];
  incomplete = mkSystem {
    systemName = "method46-initial-incomplete";
    modules = [
      ../../systems/server.nix
      {
        aos.sandbox.method46InitialFloors = lib.genAttrs purposes (_: {enable = true;});
      }
    ];
  };
  rejects = message: system:
    builtins.any (check: check.message == message && !check.assertion) system.config.assertions;
  parentMessage = purpose: "Manual ${purpose} floor initialization requires explicit, separate Parent06 receiving and sender subdivisions.";
  credentialMessage = purpose: "Manual ${purpose} floor initialization requires its independent public approval pin and the actual normal owners' complete external public credential sources.";
  policyMessage = purpose: "Manual ${purpose} floor initialization requires the selected production policy's independent service/helper roles and fixed image labels.";
  listenerMessage = purpose: "Manual ${purpose} floor initialization requires its fixed service context and original approval and public-output delivery.";
  manualMessage = "Manual initial-floor units must remain unbootstrapped, argument-free and bound to their exact original delivery; normal startup cannot initialize.";
  sourceListener = builtins.readFile ../../crates/sandbox/controller/aos-sandbox-controller-domain/src/method46_initial_startup/approval_listener.rs;
  managerPatch = builtins.readFile ../../pkgs/system/patches/0041-method46-initial-parent06.patch;
  socketContract = purpose: let
    socket = incomplete.config.systemd.sockets."aos-sandbox-${purpose}-floor-initialize".socketConfig;
    role =
      if purpose == "controller"
      then "ControllerStorageClient"
      else "StorageBroker";
    index =
      if purpose == "controller"
      then "0"
      else "1";
    path = socket.ListenSequentialPacket;
    nativeRole = "Method46InitialServiceRoleV1::${role}";
    pattern = ".*${lib.escapeRegex nativeRole}[[:space:]]*=>[[:space:]]*[{][[:space:]]*\"${lib.escapeRegex path}\"[[:space:]]*[}].*";
  in
    socket.FileDescriptorName
    == "aos-method46-initial-approval"
    && builtins.match pattern sourceListener != null
    && lib.hasInfix "initial_index == ${index} ? \"${path}\"" managerPatch;

  incompleteAssertions = assert incomplete.config.aos.sandbox.resourceBank.parentEnclosure == null;
  assert builtins.all (purpose: incomplete.config.aos.sandbox.method46InitialFloors.${purpose}.enable) purposes;
    builtins.all (purpose:
      socketContract purpose
      && rejects (parentMessage purpose) incomplete
      && rejects (credentialMessage purpose) incomplete
      && rejects (policyMessage purpose) incomplete)
    purposes;

  # Exercise the listener assertion independently of the unavailable installed
  # policy and funding. Each override must invalidate an otherwise valid
  # listener, rather than merely observing an unrelated admission failure.
  listenerOverrides = purpose: let
    foreign =
      if purpose == "controller"
      then "storage"
      else "controller";
  in [
    {Service = "aos-sandbox-${foreign}-floor-initialize.service";}
    {ListenSequentialPacket = "/run/aos/sandbox/method46-${foreign}-initial.sock";}
    {FileDescriptorName = "foreign-approval";}
    {Accept = true;}
    {SocketUser = "nobody";}
    {SocketGroup = "nobody";}
    {SocketMode = "0666";}
    {DirectoryMode = "0755";}
    {Backlog = 2;}
    {PassCredentials = false;}
    {PassPIDFD = false;}
    {PassSecurity = true;}
    {PassSubjectBeforeListen = false;}
  ];
  listenerAssertions = builtins.all (purpose: let
    unit = "aos-sandbox-${purpose}-floor-initialize";
    hasValidListener = system:
      builtins.any (check: check.message == listenerMessage purpose && check.assertion) system.config.assertions;
    changedSocket = override:
      incomplete.extendModules {
        modules = [{systemd.sockets.${unit}.socketConfig = lib.mapAttrs (_: lib.mkForce) override;}];
      };
    changedService = override:
      incomplete.extendModules {
        modules = [{systemd.services.${unit}.serviceConfig = lib.mapAttrs (_: lib.mkForce) override;}];
      };
  in
    hasValidListener incomplete
    && builtins.all (override: rejects (listenerMessage purpose) (changedSocket override)) (listenerOverrides purpose)
    && builtins.all (override: rejects (listenerMessage purpose) (changedService override)) [
      {SELinuxContext = "system_u:system_r:init_t";}
      {StandardOutput = "inherit";}
      {StandardError = "null";}
    ])
  purposes;

  forConfigurationModules = configurationModules: let
    evaluated = mkSystem {
      systemName = "method46-initial-selected";
      modules = [../../systems/server.nix] ++ configurationModules;
    };
    cfg = evaluated.config;
    commands = import ../../modules/sandbox/_normal-floor-service-commands.nix {
      inherit lib;
      config = cfg;
    };
    selected = builtins.filter (purpose: cfg.aos.sandbox.method46InitialFloors.${purpose}.enable) purposes;
    unitName = purpose: "aos-sandbox-${purpose}-floor-initialize";
    projection = purpose: let
      name = unitName purpose;
      service = cfg.systemd.services.${name};
      socket = cfg.systemd.sockets.${name};
    in {
      inherit (service) wantedBy requiredBy;
      inherit (service) serviceConfig;
      socketWantedBy = socket.wantedBy;
      socketRequiredBy = socket.requiredBy;
      inherit (socket) socketConfig;
      normalArgv = commands.${purpose}.argv;
    };
    automatic = evaluated.extendModules {
      modules = [
        {
          systemd.services = lib.genAttrs (map unitName selected) (_: {
            wantedBy = ["multi-user.target"];
          });
        }
      ];
    };
    failedAssertions = builtins.filter (check: !check.assertion) cfg.assertions;
    validation = assert selected != [];
    assert failedAssertions == [] || throw (builtins.concatStringsSep "\n" (map (check: check.message) failedAssertions));
      rejects manualMessage automatic;
  in {
    inherit evaluated validation;
    units = lib.genAttrs selected projection;
  };
in {
  inherit incompleteAssertions listenerAssertions forConfigurationModules;
}
