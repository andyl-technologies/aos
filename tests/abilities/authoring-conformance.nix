##! tests/abilities/authoring-conformance.nix - Shared corpus Nix checks.
{
  pkgs,
  lib,
}: let
  corpus = builtins.fromJSON (builtins.readFile ./conformance/v1.json);
  abilityContractRenderer = import ../../pkgs/build-support/_ability-contract-renderer.nix {
    inherit lib;
    inherit (lib) abilities;
  };
  runner = import ./conformance/runner.nix {
    inherit (lib) abilities;
    inherit abilityContractRenderer;
  };

  unique = values:
    builtins.length values
    == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (value: {
        name = value;
        value = true;
      })
      values)));

  uniqueValues = values:
    builtins.attrNames (builtins.listToAttrs (builtins.map (value: {
        name = value;
        value = true;
      })
      values));

  portableRecordType = lib.abilities.types.record {
    fields = {
      enabled = {
        type = lib.abilities.types.boolean;
        default = true;
        description = "Whether the portable record is enabled.";
      };
      mode = lib.abilities.types.enum ["active" "passive"];
      name = lib.abilities.types.string {
        maxLength = 32;
        syntax = "local-key-v1";
      };
    };
  };
  portableRecordEvaluation = lib.evalModules {
    modules = [
      {
        options.testRecord = lib.mkOption {
          type = portableRecordType;
        };
        config.testRecord = {
          mode = "active";
          name = "example";
        };
      }
    ];
  };
  invalidPortableRecord = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        {
          options.testRecord = lib.mkOption {
            type = portableRecordType;
          };
          config.testRecord = {
            mode = "invalid";
            name = "example";
          };
        }
      ];
    }).config.testRecord
    true);
  optionalRecordType = lib.abilities.types.record {
    fields = {
      omitted = {
        type = lib.abilities.types.string {
          maxLength = 32;
          syntax = null;
        };
        optional = true;
      };
      explicitNull = lib.abilities.types.optional lib.abilities.types.boolean;
      defaulted = {
        type = lib.abilities.types.boolean;
        default = true;
      };
    };
  };
  optionalRecordEvaluation = lib.evalModules {
    modules = [
      {
        options.test = lib.mkOption {type = optionalRecordType;};
        config.test.explicitNull = null;
      }
    ];
  };
  invalidOptionalRecord = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        {
          options.test = lib.mkOption {type = optionalRecordType;};
          config.test = {
            explicitNull = null;
            unknown = true;
          };
        }
      ];
    }).config.test
    true);

  taggedVariant = lib.abilities.types.record {
    fields = {
      kind = lib.abilities.types.enum ["enabled"];
      settings = lib.abilities.types.record {
        fields.flag = {
          type = lib.abilities.types.boolean;
          default = true;
          description = "Whether the tagged variant is enabled.";
        };
      };
    };
  };
  authoredTaggedUnion = lib.abilities.types.taggedUnion {
    tag = "kind";
    variants.enabled = taggedVariant;
  };
  taggedUnionEvaluation = lib.evalModules {
    modules = [
      {
        options.test = lib.mkOption {type = authoredTaggedUnion;};
        config.test = {
          kind = "enabled";
          settings = {};
        };
      }
    ];
  };
  invalidTaggedUnion = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        {
          options.test = lib.mkOption {type = authoredTaggedUnion;};
          config.test = {
            kind = "enabled";
            settings.unknown = true;
          };
        }
      ];
    }).config.test
    true);
  decodedRecordType = lib.abilities.types.fromSchema (lib.abilities.schemas.record {
    fields.enabled = lib.abilities.schemas.boolean;
    optional = [];
  });
  invalidDecodedRecord = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        {
          options.test = lib.mkOption {type = decodedRecordType;};
          config.test = {
            enabled = true;
            unknown = true;
          };
        }
      ];
    }).config.test
    true);
  invalidResourceReference = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        {
          options.test = lib.mkOption {type = lib.abilities.types.resourceReference;};
          config.test = {
            _type = "aos-resource-reference";
            interface = {
              name = "aos.test.resource";
              abi = 1;
              descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
              unknown = true;
            };
            resource = {
              provider = plainIdentity;
              key = "resource";
            };
            operations = [];
            lifetime = "instance";
          };
        }
      ];
    }).config.test
    true);
  executableInterface = lib.abilities.declareInterface {
    name = "aos.test.executable";
    abi = 1;
    description = "Accepts a symbolic executable reference for authoring conformance.";
    requestType = lib.abilities.types.record {
      fields.executable = lib.abilities.types.executableReference;
    };
    outputs = {};
    methods = {};
    lifecycle = {
      stableResourceIdentity = true;
      releasesEphemeralOnDisable = true;
      retainsPersistentByDefault = false;
      persistentDeleteMethod = null;
    };
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "executable";
    };
  };
  executableIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration executableInterface
  );
  crossTargetInterface =
    executableInterface
    // {
      name = "aos.test.cross-target";
      description = "Provides the target resource for a cross-interface method.";
    };
  crossSourceInterface =
    executableInterface
    // {
      name = "aos.test.cross-source";
      description = "Invokes a method against a separately declared resource interface.";
      methods.invoke = {
        description = "Invokes the separately declared target resource.";
        semantics = {
          requiredTargetAccess = "exclusive-write";
          stopsProvider = false;
        };
        parameters = lib.abilities.types.boolean;
        targetResource = crossTargetInterface.name;
        outputs = {};
        permittedOperations = ["invoke"];
        guarantees = [];
        outcome = {
          completionEvidence = lib.abilities.types.boolean;
          observationEvidence = lib.abilities.types.boolean;
          supportsRejectedBeforeEffect = true;
          indeterminate = "reconcile";
        };
      };
    };
  crossTargetEvaluation = lib.evalModules {
    modules = [
      lib.abilities.module
      {
        config.aos.abilities = {
          environment = plainIdentity.environment;
          interfaces = {
            "authoring:source" = crossSourceInterface;
            "authoring:target" = crossTargetInterface;
          };
        };
      }
    ];
  };
  missingCrossTarget = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        lib.abilities.module
        {
          config.aos.abilities = {
            environment = plainIdentity.environment;
            interfaces."authoring:source" = crossSourceInterface;
          };
        }
      ];
    }).config.aos.abilities.interfaces
    true);
  executableModule = {
    entryPoint,
    selector,
    description ? "Accepts a symbolic executable reference for authoring conformance.",
  }: {
    config.aos.abilities = {
      environment = plainIdentity.environment;
      interfaces."authoring:executable" = executableInterface // {inherit description;};
      instances."authoring:consumer" = {};
      requirementTemplates."authoring:executable" = {
        description = "Requires the executable-reference conformance interface.";
        interface = executableIdentity.name;
        inherit (executableIdentity) abi descriptor;
      };
      requests."authoring:executable" = {
        requirement = "authoring:executable";
        consumer = "authoring:consumer";
        parameters.executable = {
          artifact = selector;
          entry_point = entryPoint;
          arguments = [
            "--serve"
            (lib.abilities.resultOf "configuration" "path")
          ];
        };
      };
    };
  };
  validExecutableRequest = lib.evalModules {
    modules = [
      lib.abilities.module
      (executableModule {
        entryPoint = "bin/server";
        selector = selfOutput;
      })
    ];
  };

  canonicalAbilityEvaluation = lib.evalModules {
    modules = [
      lib.abilities.module
      {
        config.aos.abilities.requirementTemplates.database = {
          description = "Requires the database lifecycle methods used by this conformance case.";
          interface = "aos.test.database";
          abi = 1;
          descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
          methods = ["start" "stop"];
        };
      }
    ];
  };
  invalidCanonicalAbility = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        lib.abilities.module
        {
          config.aos.abilities.requirementTemplates.database = {
            description = "Malformed requirement used to exercise strict nested rejection.";
            interface = "aos.test.database";
            abi = 1;
            descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            unknown = true;
          };
        }
      ];
    }).config.aos.abilities.requirementTemplates
    true);

  implementationDefinition = lib.abilities.define {
    interface = "aos.test.symbolic-artifact";
    abi = 1;
    requestSchema = lib.abilities.types.boolean;
    outputs.flag = {
      schema = lib.abilities.types.boolean;
      phase = "planning";
      visibility = "protected";
      lifetime = "instance";
    };
    methods = {};
    lifecycle = {
      stableResourceIdentity = true;
      releasesEphemeralOnDisable = true;
      retainsPersistentByDefault = true;
      persistentDeleteMethod = null;
    };
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "symbolic-artifact";
    };
    requires = {};
    ownsResourceKinds = [];
    composeEntry = "compose";
    transitionEntry = "transition";
    compose = context: context;
    transition = context: context;
  };
  evaluateImplementation = implementation:
    (lib.evalModules {
      modules = [
        lib.abilities.module
        {
          config.aos.abilities = lib.abilities.qualifyPackageAbilities "authoring" (
            lib.abilities.projectDefinitions {test = implementation;}
          );
        }
      ];
    }).config.aos.abilities;
  rejectsImplementation = implementation:
    !(builtins.tryEval (builtins.deepSeq (evaluateImplementation implementation) true)).success;
  localImplementationProjection = lib.abilities.projectDefinitions {test.definition = implementationDefinition;};
  alphaImplementationProjection = lib.abilities.qualifyPackageAbilities "alpha" localImplementationProjection;
  betaImplementationProjection = lib.abilities.qualifyPackageAbilities "beta" localImplementationProjection;
  combinedImplementationKeys = builtins.attrNames (
    alphaImplementationProjection.implementations
    // betaImplementationProjection.implementations
  );
  packageModuleFor = package: {
    name = package;
    module = {
      imports = [
        {config.aos.abilities = lib.abilities.projectDefinitions {test.definition = implementationDefinition;};}
        {config.aos.abilities.implementations.test.provide = context: context;}
      ];
    };
  };
  combinedPackageEvaluation = lib.evalModules {
    modules = [lib.abilities.module];
    packageModules = [
      (packageModuleFor "alpha")
      (packageModuleFor "beta")
    ];
  };
  qualifiedDeferredRequest = lib.abilities.qualifyPackageAbilities "alpha" {
    requests.consumer = {
      package = null;
      requirement = "service";
      consumer = "consumer";
      scope = [];
      parameters = {
        literal = "producer";
        nested = [
          (lib.abilities.resultOf "producer" "path")
        ];
      };
    };
  };
  selfOutput = lib.abilities.packageOutput {};
  namedOutput = lib.abilities.packageOutput {
    package = "aos";
    output = "packageRuntime";
  };
  forgedSelector = package: output: {
    _type = "aos-package-output-selector";
    inherit package output;
  };
  handlerImplementation = artifact: entryPoint: {
    artifact = selfOutput;
    definition = implementationDefinition // {handler = "test-handler";};
    handler = {
      inherit artifact entryPoint;
      arguments = lib.abilities.types.boolean;
      result = lib.abilities.types.boolean;
    };
  };
  rejectsAbilityModule = module:
    !(builtins.tryEval (builtins.deepSeq
      (lib.evalModules {
        modules = [lib.abilities.module module];
      }).config.aos.abilities
      true)).success;
  plainIdentity = {
    environment = {
      authority = "deployment";
      key = "test";
      stage = "host";
    };
    key = "instance";
  };
  invalidPackageOutputField = builtins.tryEval (builtins.deepSeq
    (lib.abilities.packageOutput {unknown = true;})
    true);
  invalidPackageOutputKey = builtins.tryEval (builtins.deepSeq
    (lib.abilities.packageOutput {package = "bad/package";})
    true);

  recipeIsBounded = case: let
    arguments = case.arguments;
    depth = arguments.depth or 0;
    items = arguments.items or arguments.count or arguments.chunks or 0;
    generatedBytes =
      if arguments ? chunk_bytes && arguments ? count
      then arguments.chunk_bytes * arguments.count
      else 0;
  in
    depth
    <= corpus.recipe_limits.max_generated_depth
    && items <= corpus.recipe_limits.max_generated_items
    && generatedBytes <= corpus.recipe_limits.max_generated_string_bytes;

  checkAcceptedCase = case: let
    evaluated = builtins.tryEval (builtins.deepSeq (runner.evaluate case) (runner.evaluate case));
  in
    if case.expected.outcome == "accept"
    then evaluated.success && (!(case.expected ? value) || evaluated.value == case.expected.value)
    else true;

  coverageFor = consumer: namespace:
    uniqueValues (builtins.concatLists (builtins.map (
        case: (runner.coverage case).${namespace}
      )
      (builtins.filter (case: builtins.elem consumer case.consumers) corpus.cases)));

  nixCases = builtins.filter (case: builtins.elem "nix" case.consumers) corpus.cases;
  caseIds = builtins.map (case: case.id) corpus.cases;
  coverageCases =
    builtins.filter (
      case:
        builtins.any (namespace: (runner.coverage case).${namespace} != []) [
          "abilities"
          "effects"
          "schemas"
        ]
    )
    corpus.cases;
  directFixture = pkgs.mkDerivation {
    pname = "aos-ability-authoring-direct-fixture";
    version = "1";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib" "$out/conformance"
          cp -R ${../../lib}/. "$out/lib/"
          cp ${./conformance/direct.nix} "$out/direct.nix"
          cp ${./conformance/runner.nix} "$out/runner.nix"
          cp ${../../pkgs/build-support/_ability-contract-renderer.nix} "$out/ability-contract-renderer.nix"
          cp ${./conformance/provider.nix} "$out/conformance/provider.nix"
          cp ${./composition.nix} "$out/composition.nix"
          cp ${./effects.nix} "$out/effects.nix"
        '';
      }
    ];
  };
in
  assert corpus.schema == "aos.ability.authoring-conformance/v1";
  assert corpus.recipe_limits
  == {
    max_generated_depth = 64;
    max_generated_items = 2000000;
    max_generated_string_bytes = 34603008;
  };
  assert unique caseIds;
  assert builtins.all (case: case.consumers != [] && unique case.consumers) corpus.cases;
  assert builtins.all recipeIsBounded corpus.cases;
  # Any public helper addition must extend the checked-in corpus inventory.
  assert corpus.public_helpers.abilities == builtins.attrNames lib.abilities;
  assert corpus.public_helpers.schemas == builtins.attrNames lib.abilities.schemas;
  assert corpus.public_helpers.effects == builtins.attrNames lib.abilities.effects;
  assert builtins.attrNames (lib.abilities.module {config = null;}).options == ["aos"];
  assert canonicalAbilityEvaluation.config.aos.abilities.requirementTemplates.database
  == {
    abi = 1;
    description = "Requires the database lifecycle methods used by this conformance case.";
    descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fallback = null;
    guarantees = [];
    interface = "aos.test.database";
    methods = ["start" "stop"];
    strength = "required";
  };
  assert !invalidCanonicalAbility.success;
  assert optionalRecordEvaluation.config.test
  == {
    defaulted = true;
    explicitNull = null;
  };
  assert !invalidOptionalRecord.success;
  assert selfOutput
  == {
    _type = "aos-package-output-selector";
    output = "out";
    package = "self";
  };
  assert namedOutput.output == "packageRuntime";
  assert !invalidPackageOutputField.success;
  assert !invalidPackageOutputKey.success;
  assert (evaluateImplementation {definition = implementationDefinition;}).implementations."authoring:test".interface == "authoring:test";
  assert combinedImplementationKeys == ["alpha:test" "beta:test"];
  assert builtins.attrNames combinedPackageEvaluation.config.aos.abilities.implementations == ["alpha:test" "beta:test"];
  assert builtins.isFunction combinedPackageEvaluation.config.aos.abilities.implementations."alpha:test".provide;
  assert qualifiedDeferredRequest.requests."alpha:consumer".parameters.literal == "producer";
  assert (builtins.head qualifiedDeferredRequest.requests."alpha:consumer".parameters.nested).request == "alpha:producer";
  assert alphaImplementationProjection.implementations."alpha:test".package == "alpha";
  assert alphaImplementationProjection.implementations."alpha:test".interface == "alpha:test";
  assert rejectsImplementation {
    artifact = pkgs.bash;
    definition = implementationDefinition;
  };
  assert rejectsImplementation {
    artifact = "/nix/store/00000000000000000000000000000000-artifact";
    definition = implementationDefinition;
  };
  assert rejectsImplementation {
    artifacts = [pkgs.bash];
    definition = implementationDefinition;
  };
  assert rejectsImplementation {
    artifact = forgedSelector "bad/package" "out";
    definition = implementationDefinition;
  };
  assert rejectsImplementation {
    artifact = forgedSelector "self" "bad/output";
    definition = implementationDefinition;
  };
  assert rejectsImplementation {
    artifact = (forgedSelector "self" "out") // {unknown = true;};
    definition = implementationDefinition;
  };
  assert rejectsImplementation (handlerImplementation pkgs.bash "bin/handler");
  assert rejectsImplementation (handlerImplementation selfOutput "/bin/handler");
  assert rejectsImplementation (handlerImplementation selfOutput "");
  assert rejectsImplementation (handlerImplementation selfOutput "bin//handler");
  assert rejectsImplementation (handlerImplementation selfOutput "bin/./handler");
  assert rejectsImplementation (handlerImplementation selfOutput "bin/../handler");
  assert rejectsImplementation ((handlerImplementation selfOutput "bin/handler")
    // {
      handler.arguments = lib.abilities.schemas.boolean;
    });
  assert rejectsImplementation {
    definition =
      implementationDefinition
      // {
        _interface_declaration.lifecycle.unknown = true;
      };
  };
  assert rejectsAbilityModule {
    config.aos.abilities =
      (lib.abilities.projectDefinitions {
        test.definition =
          implementationDefinition
          // {
            _interface_declaration.configurationType = lib.abilities.schemas.boolean;
          };
      })
      // {
        environment = plainIdentity.environment;
        instances.test = {
          implementation = "test";
          configuration = "not-a-boolean";
        };
      };
  };
  assert rejectsAbilityModule {
    config.aos.abilities =
      (lib.abilities.projectDefinitions {test.definition = implementationDefinition;})
      // {
        environment = plainIdentity.environment;
        instances.consumer = {};
        requirementTemplates.test = {
          description = "Requires the symbolic artifact test interface.";
          interface = "aos.test.symbolic-artifact";
          abi = 1;
          descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
          strength = "advisory";
          fallback.outputs.flag = "not-a-boolean";
        };
      };
  };
  assert rejectsAbilityModule {
    config.aos.abilities =
      (lib.abilities.projectDefinitions {test.definition = implementationDefinition;})
      // {
        environment = plainIdentity.environment;
        instances.consumer = {};
        requirementTemplates.test = {
          description = "Requires the symbolic artifact test interface.";
          interface = "aos.test.symbolic-artifact";
          abi = 1;
          descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        };
        requests.test = {
          requirement = "test";
          consumer = "consumer";
          parameters = "not-a-boolean";
        };
      };
  };
  assert rejectsAbilityModule {
    config.aos.abilities.bindings.test = {
      request = "test";
      implementation = "test";
      providerInstance = "bad/instance";
      slot = "test";
    };
  };
  assert rejectsAbilityModule {
    config.aos.abilities =
      (lib.abilities.projectDefinitions {test.definition = implementationDefinition;})
      // {
        desiredResources.test = {
          kind = "aos.test.symbolic-artifact";
          controller = "test";
          lifetime = "instance";
          value = "not-a-boolean";
        };
      };
  };
  assert portableRecordEvaluation.config.testRecord
  == {
    enabled = true;
    mode = "active";
    name = "example";
  };
  assert taggedUnionEvaluation.config.test.settings.flag;
  assert !invalidTaggedUnion.success;
  assert !invalidDecodedRecord.success;
  assert !invalidResourceReference.success;
  assert validExecutableRequest.config.aos.abilities.requests."authoring:executable".parameters.executable.entry_point == "bin/server";
  assert crossTargetEvaluation.config.aos.abilities.interfaces."authoring:source".methods.invoke.targetResource == crossTargetInterface.name;
  assert !missingCrossTarget.success;
  assert rejectsAbilityModule (executableModule {
    entryPoint = "/bin/server";
    selector = selfOutput;
  });
  assert rejectsAbilityModule (executableModule {
    entryPoint = "bin/server";
    selector = selfOutput // {unknown = true;};
  });
  assert rejectsAbilityModule (executableModule {
    entryPoint = "bin/server";
    selector = selfOutput;
    description = "";
  });
  assert rejectsAbilityModule (executableModule {
    entryPoint = "bin/server";
    selector = selfOutput;
    description = builtins.concatStringsSep "" (builtins.genList (_: "x") 4097);
  });
  assert lib.abilities.types.schemaOf "portable record" portableRecordType
  == {
    fields = {
      enabled = {kind = "boolean";};
      mode = {
        kind = "string-enum";
        values = ["active" "passive"];
      };
      name = {
        kind = "string";
        max_length = 32;
        syntax = "local-key-v1";
      };
    };
    kind = "record";
    optional_fields = ["enabled"];
  };
  assert !invalidPortableRecord.success;
  assert builtins.all checkAcceptedCase nixCases;
  assert builtins.all (
    case: builtins.all (consumer: builtins.elem consumer case.consumers) ["nix" "evaluator"]
  )
  coverageCases;
  assert builtins.all (
    consumer:
      builtins.all (
        namespace: coverageFor consumer namespace == corpus.public_helpers.${namespace}
      ) ["abilities" "effects" "schemas"]
  ) ["nix" "evaluator"];
    pkgs.mkDerivation {
      pname = "aos-ability-authoring-conformance-v1";
      version = "0";
      src = null;
      buildDeps = [pkgs.jq pkgs.nix pkgs.grep];
      phases = [
        {
          name = "check";
          script = ''
            export HOME="$TMPDIR/home"
            export NIX_STATE_DIR="$TMPDIR/nix-state"
            export NIX_CONF_DIR="$TMPDIR/nix-conf"
            mkdir -p "$HOME" "$NIX_STATE_DIR/profiles" "$NIX_CONF_DIR"

            rejection_cases="$TMPDIR/nix-rejections.jsonl"
            ${pkgs.jq}/bin/jq -c \
              '.cases[] | select(.consumers | index("nix")) | select(.expected.outcome == "reject")' \
              ${./conformance/v1.json} > "$rejection_cases"

            tested=0
            while IFS= read -r case_json; do
              case_id="$(printf '%s\n' "$case_json" | ${pkgs.jq}/bin/jq -r '.id')"
              expected_code="$(printf '%s\n' "$case_json" | ${pkgs.jq}/bin/jq -r '.expected.code')"

              if diagnostic="$(${pkgs.nix}/bin/nix-instantiate \
                --eval --strict --json \
                --argstr caseJson "$case_json" \
                --argstr system ${lib.escapeShellArg pkgs.stdenv.buildPlatform.system} \
                ${directFixture}/direct.nix 2>&1)"; then
                echo "ability authoring case '$case_id' unexpectedly succeeded" >&2
                exit 1
              fi

              markers="$(printf '%s\n' "$diagnostic" \
                | ${pkgs.grep}/bin/grep -o 'AOS_ABILITY_DIAGNOSTIC_V1\[[a-z0-9-]*\]' \
                | ${pkgs.coreutils}/bin/sort -u || true)"
              if [ "$markers" != "AOS_ABILITY_DIAGNOSTIC_V1[$expected_code]" ]; then
                echo "ability authoring case '$case_id' returned '$markers', expected '$expected_code'" >&2
                printf '%s\n' "$diagnostic" >&2
                exit 1
              fi

              tested=$((tested + 1))
            done < "$rejection_cases"

            if [ "$tested" -eq 0 ]; then
              echo "ability authoring corpus contains no direct Nix rejection cases" >&2
              exit 1
            fi

            mkdir -p "$out"
            cp ${./conformance/v1.json} "$out/corpus.json"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
