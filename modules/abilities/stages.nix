##! Stage-specific ability fixed-point contributions.
##!
##! The system constructor evaluates each stage with the same authenticated
##! package modules selected by the parent system. Feature modules contribute
##! ordinary ability modules here; they do not copy interfaces, package lists,
##! requests, or resource identities into a parallel configuration format.
{
  config,
  lib,
  initrdAbilityEvaluation ? null,
  ...
}: {
  options = {
    aos.abilities.stages.initrd = {
      modules = lib.mkOption {
        type = lib.types.listOf lib.types.anything;
        default = [];
        internal = true;
        description = ''
          Ordinary modules evaluated in the authenticated initrd ability
          environment after the parent system selects its package modules.
        '';
      };
    };

    system.build.initrdAbilityGraph = lib.mkOption {
      type = lib.types.anything;
      readOnly = true;
      internal = true;
      description = ''
        Complete checked initrd ability fixed point used to build the signed
        stage selection and retained handoff evidence.
      '';
    };
  };

  config.system.build.initrdAbilityGraph =
    if initrdAbilityEvaluation == null
    then null
    else initrdAbilityEvaluation.config.aos.abilities;
}
