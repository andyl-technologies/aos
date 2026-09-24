##! Production util-linux getty declarations in host and initrd fixed points.
{
  lib,
  pkgs,
  mkSystem,
}: let
  environment = stage: {
    authority = "test";
    key = "util-linux-getty";
    inherit stage;
  };
  evaluate = stage: modules:
    lib.evalModules {
      inherit lib;
      modules =
        [
          ../../modules/abilities/default.nix
          {aos.abilities.environment = environment stage;}
        ]
        ++ modules;
      packageModules = [
        {
          name = "util-linux";
          inherit (pkgs.util-linux) version;
          module = pkgs.util-linux.module + "/module.nix";
        }
      ];
    };
  disabled = evaluate "host" [];
  host = evaluate "host" [
    {aos.services.getty.autologin.enable = true;}
  ];
  disabledConsoleServices = evaluate "host" [
    {aos.services.getty.autologin.enable = true;}
    ({lib, ...}: {
      aos.services."getty.virtual-console".enable = lib.mkForce false;
      aos.services."getty.serial-console".enable = lib.mkForce false;
    })
  ];
  initrd = evaluate "initrd" [
    {
      aos.services.getty.autologin = {
        enable = true;
        stage = "initrd";
      };
    }
  ];
  invalidStage = builtins.tryEval (builtins.deepSeq (
      (evaluate "host" [{aos.services.getty.autologin.stage = "build";}]).config
    )
    true);
  hostRequests = host.config.aos.abilities.requests;
  initrdRequests = initrd.config.aos.abilities.requests;
  request = requests: name: requests."util-linux:${name}".parameters;
  qualifiedResultOf = requestName: output: {
    _type = "aos-request-output-reference";
    request = requestName;
    inherit output;
  };
  hostVirtual = request hostRequests "virtual-console-lifecycle";
  hostVirtualDependencies = request hostRequests "virtual-console-dependencies";
  hostVirtualTerminal = request hostRequests "virtual-console-terminal";
  initrdVirtual = request initrdRequests "virtual-console-lifecycle";
  initrdVirtualDependencies = request initrdRequests "virtual-console-dependencies";
  initrdVirtualTerminal = request initrdRequests "virtual-console-terminal";
  # Exercise real host and initrd selection without evaluating the fleet image.
  debugSystem = mkSystem {
    modules = [
      ../../systems/_ability-providers.nix
      ../../systems/_artifact-backend.nix
      ../../systems/_kernel.nix
      ../../systems/_system-manager.nix
      {
        aos.profiles.debug = {
          enable = true;
          autologin = true;
        };
      }
    ];
    systemName = "debug-profile-getty";
  };
  debugConfig = debugSystem.config;
  debugPackageNames =
    builtins.map
    (package: package.pname or package.name)
    debugConfig.environment.systemPackages;
  debugInitrdPackageNames =
    builtins.map
    (package: package.pname or package.name)
    debugConfig.aos.boot.initrd.packageRoots;
  debugHostRequests = debugConfig.aos.abilities.requests;
  debugInitrdRequests = debugConfig.system.build.initrdAbilityGraph.requests;
  portableOptionTree = options:
    builtins.all (option:
      if (option._type or null) == "option"
      then option.type ? _abilitySchema
      else portableOptionTree option)
    (builtins.attrValues options);
in
  assert disabled.config.aos.abilities.requests == {};
  assert disabledConsoleServices.config.aos.abilities.requests == {};
  assert disabledConsoleServices.config.aos.abilities.requirementTemplates == host.config.aos.abilities.requirementTemplates;
  assert builtins.attrNames pkgs.util-linux.abilities.requirementTemplates
  == [
    "activation-milestone"
    "serial-console-service-dependencies"
    "serial-console-service-lifecycle"
    "serial-console-service-readiness"
    "serial-console-service-terminal"
    "virtual-console-service-dependencies"
    "virtual-console-service-lifecycle"
    "virtual-console-service-readiness"
    "virtual-console-service-terminal"
  ];
  assert portableOptionTree (lib.submoduleOptions host.options.aos.services.type._elementType ["aos" "services" "getty"]).autologin;
  assert !invalidStage.success;
  assert builtins.attrNames host.config.aos.abilities.instances == ["util-linux:getty"];
  assert (request hostRequests "startup-milestone").milestone == "interactive-console";
  assert (request hostRequests "user-sessions-milestone").milestone == "user-sessions-ready";
  assert hostVirtual.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "util-linux";};
        entry_point = "libexec/aos-autologin-getty";
        arguments = ["--noclear" "tty1" "linux"];
      };
      ignore_failure = false;
    }
  ];
  assert hostVirtualDependencies.after == [(qualifiedResultOf "util-linux:user-sessions-milestone" "resource")];
  assert hostVirtualDependencies.wanted_by == [(qualifiedResultOf "util-linux:startup-milestone" "resource")];
  assert hostVirtualDependencies.implicit_dependencies;
  assert hostVirtualTerminal
  == {
    service = "virtual-console";
    enabled = true;
    device = "/dev/tty1";
    reset = true;
    hangup = true;
    deallocate = true;
    send_hangup_on_stop = true;
    start_when_idle = true;
    session_identifier = "tty1";
  };
  assert builtins.attrNames (builtins.removeAttrs hostRequests ["util-linux:user-sessions-milestone"])
  == builtins.attrNames initrdRequests;
  assert !(builtins.hasAttr "util-linux:user-sessions-milestone" initrdRequests);
  assert (request initrdRequests "startup-milestone").milestone == "early-system";
  assert (builtins.head initrdVirtual.start).executable.arguments == ["--noclear" "tty0" "linux"];
  assert initrdVirtualDependencies.after == [];
  assert initrdVirtualDependencies.wanted_by == [(qualifiedResultOf "util-linux:startup-milestone" "resource")];
  assert !initrdVirtualDependencies.implicit_dependencies;
  assert initrdVirtualTerminal.device == "/dev/tty0";
  assert !initrdVirtualTerminal.deallocate;
  assert !initrdVirtualTerminal.send_hangup_on_stop;
  assert !initrdVirtualTerminal.start_when_idle;
  assert !(initrdVirtualTerminal ? session_identifier);
  assert debugConfig.aos.services.getty.autologin.enable;
  assert builtins.elem "util-linux" debugPackageNames;
  assert builtins.elem "util-linux" debugInitrdPackageNames;
  assert builtins.elem "systemd" debugInitrdPackageNames;
  assert builtins.hasAttr "util-linux:virtual-console-terminal" debugHostRequests;
  assert builtins.hasAttr "util-linux:user-sessions-milestone" debugHostRequests;
  assert builtins.hasAttr "util-linux:virtual-console-terminal" debugInitrdRequests;
  assert !(builtins.hasAttr "util-linux:user-sessions-milestone" debugInitrdRequests); true
