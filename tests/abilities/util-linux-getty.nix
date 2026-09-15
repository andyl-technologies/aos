##! Production util-linux getty declarations in host and initrd fixed points.
{
  lib,
  pkgs,
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
  portableOptionTree = options:
    builtins.all (option:
      if (option._type or null) == "option"
      then option.type ? _abilitySchema
      else portableOptionTree option)
    (builtins.attrValues options);
in
  assert disabled.config.aos.abilities.requests == {};
  assert builtins.attrNames pkgs.util-linux.abilities.requirementTemplates
  == [
    "activation-milestone"
    "service-dependencies"
    "service-lifecycle"
    "service-readiness"
    "service-terminal"
  ];
  assert portableOptionTree host.options.aos.services.getty.autologin;
  assert !invalidStage.success;
  assert builtins.attrNames host.config.aos.abilities.instances == ["util-linux:getty"];
  assert builtins.length (builtins.attrNames hostRequests) == 10;
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
  assert hostVirtualDependencies.after == [(qualifiedResultOf "util-linux:user-sessions-milestone" "readiness-resource")];
  assert hostVirtualDependencies.wanted_by == [(qualifiedResultOf "util-linux:startup-milestone" "readiness-resource")];
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
  };
  assert builtins.length (builtins.attrNames initrdRequests) == 9;
  assert !(builtins.hasAttr "util-linux:user-sessions-milestone" initrdRequests);
  assert (request initrdRequests "startup-milestone").milestone == "early-system";
  assert (builtins.head initrdVirtual.start).executable.arguments == ["--noclear" "tty0" "linux"];
  assert initrdVirtualDependencies.after == [];
  assert initrdVirtualDependencies.wanted_by == [(qualifiedResultOf "util-linux:startup-milestone" "readiness-resource")];
  assert !initrdVirtualDependencies.implicit_dependencies;
  assert initrdVirtualTerminal.device == "/dev/tty0";
  assert !initrdVirtualTerminal.deallocate;
  assert !initrdVirtualTerminal.send_hangup_on_stop;
  assert !initrdVirtualTerminal.start_when_idle; true
