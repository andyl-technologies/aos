##! Focused original registry/trust policy and native metadata anchor projection.
let
  lib = import ../../lib {system = "x86_64-linux";};
  package = {
    type = "derivation";
    name = "aos-metadata-provider";
    outPath = import ./_fixture-payload.nix "metadata";
    meta.mainProgram = "aos-metadata-policy-provider";
  };
  key = "ops:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIJiuCf/fX/rsn5ODyT5ebEVtabAmZceKi2aD+cBWjWKL";
  evaluate = configuration:
    lib.evalModules {
      inherit lib;
      specialArgs = {inherit package;};
      modules = [
        ../../lib/effects/module.nix
        ../../modules/base/apm-registries.nix
        ../../modules/base/config-eval.nix
        ../../pkgs/tools/_aos-metadata-provider/module.nix
        {
          # These declarations isolate image projection outputs. Policy and
          # metadata contracts are imported from their actual owning sources.
          options.environment.etc = lib.mkOption {
            type = lib.types.attrsOf (lib.types.submodule {options.text = lib.mkOption {type = lib.types.str;};});
            default = {};
          };
          options.aos.packageRuntime.configurationEvaluation = lib.mkOption {
            type = lib.types.attrs;
            default = {};
          };
          options.aos.boot.secureBoot.measuredBoot = {
            enable = lib.mkOption {
              type = lib.types.bool;
              default = false;
            };
            _effectivePcrPublicKey = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
            };
          };
        }
        configuration
      ];
    };
  valid = evaluate {
    aos.apm.configKeys.ops = [key];
    aos.config.evalAtBoot.trust = "signed";
  };
  retained = lib.evalModules {
    inherit lib;
    specialArgs = {inherit package;};
    modules = [
      ../../lib/effects/module.nix
      ../../pkgs/tools/_aos-metadata-provider/module.nix
      {
        aos.apm.configKeys.ops = [key];
        aos.config.evalAtBoot.trust = "signed";
      }
    ];
  };
  policy = valid.config.aos.metadata.storageProvisioning.authorizationConfiguration;
  anchor = builtins.head policy.trusted_config_keys;
  assertionsPass = evaluated: builtins.all (entry: entry.assertion) evaluated.config.assertions;
  rejects = configuration: let
    attempted = builtins.tryEval (builtins.deepSeq (assertionsPass (evaluate configuration)) (assertionsPass (evaluate configuration)));
  in
    !attempted.success || !attempted.value;
  default = evaluate {};
  registry = evaluate {
    aos.apm.registries.example = {
      url = "https://registry.example/aos";
      trustKeys = ["example:Ed25519:QUJDREVGR0g=" "example:Ed25519:SUpLTE1OT1A="];
      caches = [{url = "file:///var/lib/aos-cache";}];
      rootOwnerSigners = ["release-provenance"];
    };
  };
in {
  retainedNativePolicy = assert retained.config.aos.metadata.storageProvisioning.authorizationConfiguration == policy;
  assert assertionsPass retained; true;
  platformTrustDefault = assert default.config.aos.config.evalAtBoot.trust == "platform"; assert default.config.aos.metadata.storageProvisioning.authorizationConfiguration.trust_mode == "platform"; true;
  signedPolicy = assert assertionsPass valid; assert policy.trust_mode == "signed"; true;
  exactNativeAnchor = assert builtins.readFile anchor.path == "${key}\n"; assert anchor.content_sha256 == "sha256:${builtins.hashString "sha256" "${key}\n"}"; true;
  originalAnchorProjection = assert valid.config.environment.etc."apm/trusted-config-keys.d/ops.pub".text == "${key}\n"; true;
  malformedKeyRejected = assert rejects {aos.apm.configKeys.ops = ["not-a-key"];}; true;
  mismatchedOperatorRejected = assert rejects {aos.apm.configKeys.ops = ["other:Ed25519:QUJDREVGR0g="];}; true;
  emptyAnchorRejected = assert rejects {aos.apm.configKeys.ops = [];}; true;
  signedWithoutAnchorRejected = assert rejects {aos.config.evalAtBoot.trust = "signed";}; true;
  registryRotation = assert registry.config.environment.etc."apm/trusted-keys.d/example.pub".text == "example:Ed25519:QUJDREVGR0g=\nexample:Ed25519:SUpLTE1OT1A=\n"; assert lib.hasInfix "public_key = \"example:Ed25519:QUJDREVGR0g=\"" registry.config.environment.etc."apm/registries.d/example.toml".text; true;
  registryRootOwnerPolicy = assert registry.config.aos.apm.registries.example.rootOwnerSigners == ["release-provenance"]; assert lib.hasInfix ''root_owner_signers = ["release-provenance"]'' registry.config.environment.etc."apm/registries.d/example.toml".text; true;
  defaultRegistryRootOwnerPolicy = assert default.config.aos.apm.registries.andyl.rootOwnerSigners == []; true;
  invalidRegistryNameRejected = assert rejects {
    aos.apm.registries."../foreign" = {
      url = "https://registry.example/aos";
      trustKeys = ["../foreign:Ed25519:QUJDREVGR0g="];
    };
  }; true;
  noUnadmittedLibraryAuthority = assert !((lib.submoduleOptions valid.config.aos.abilities.metadata.operations.authorize.input.options.configuration.type []) ? base_library); true;
}
