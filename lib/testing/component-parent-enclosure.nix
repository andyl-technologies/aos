##! Checks nullable parent-enclosure audit projection through actual modules.
##!
##! These typed fixtures exercise definition collection without materializing
##! an enclosure or admitting a resource policy or runtime effect.
{lib}: let
  auditBounds = {
    maxLogFileMiB = 1;
    numLogs = 2;
    maximumRules = 1;
    maximumRuleBytes = 1;
    maximumBacklog = 1;
  };
  profile = {
    manager = {};
    fixedServices = {};
    managerOpenFilesPerProcess = 1;
    fixedOpenFilesPerProcess = 1;
    journal = {
      systemMaxUse = 1;
      systemMaxFileSize = 1;
      runtimeMaxUse = 1;
      runtimeMaxFileSize = 1;
    };
    audit = auditBounds;
  };
  evaluate = parentEnclosure: extraModules:
    (lib.evalModules {
      inherit lib;
      modules =
        [
          ../../modules/sandbox/component-parent-enclosure.nix
          ({
            config,
            lib,
            pkgs,
            ...
          }: let
            auditModule = import ../../modules/security/audit.nix {inherit config lib pkgs;};
          in {
            # Use the real receiving schema; unrelated audit effects stay lazy.
            options.aos.security.audit.bounds = auditModule.options.aos.security.audit.bounds;
            options.environment.etc = lib.mkOption {
              type = lib.types.attrs;
              default = {};
            };
          })
          {aos.sandbox.resourceBank.parentEnclosure = parentEnclosure;}
        ]
        ++ extraModules;
    })
    .config;

  disabled = evaluate null [];
  independent = evaluate null [{aos.security.audit.bounds = auditBounds;}];
  selected = evaluate profile [];
  invalid = evaluate (profile // {audit = auditBounds // {numLogs = 1;};}) [];
  invalidBounds = builtins.tryEval (builtins.deepSeq invalid.aos.security.audit.bounds true);
  boundsData = value: builtins.removeAttrs value ["_module"];
in
  disabled.aos.security.audit.bounds
  == null
  && disabled.environment.etc == {}
  && boundsData independent.aos.security.audit.bounds == auditBounds
  && independent.environment.etc == {}
  && boundsData selected.aos.security.audit.bounds == auditBounds
  && !invalidBounds.success
