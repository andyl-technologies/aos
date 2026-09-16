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
}: let
  resolutionInputType = lib.types.submodule {
    options = {
      desiredInput = lib.mkOption {
        type = lib.types.path;
        description = "Canonical aos.ability.activation-desired/v1 build input.";
      };
      authenticatedPolicySet = lib.mkOption {
        type = lib.types.path;
        description = "Canonical aos.ability.authenticated-policy-set/v1 build input.";
      };
    };
  };
in {
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

      packages = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [];
        internal = true;
        description = ''
          Parent-selected packages whose authenticated native modules participate
          in the initrd fixed point. Selection does not add payload dependency
          edges beyond the package's existing initrd inclusion.
        '';
      };

      intent = lib.mkOption {
        type = lib.types.attrs;
        default = {};
        internal = true;
        description = ''
          Data-only initrd module configuration retained as the hermetic
          build-stage evaluator input. Package modules remain authoritative for
          their declarations, implementations, and composition behavior.
        '';
      };

      resolutionInput = lib.mkOption {
        type = lib.types.nullOr resolutionInputType;
        default = null;
        internal = true;
        description = ''
          Canonical desired-state and authenticated policy documents projected
          from the final explicit initrd composition and its exact retained
          package contracts. This option defines no separate provider catalog.
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
