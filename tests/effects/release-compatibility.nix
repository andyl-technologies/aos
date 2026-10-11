##! Checks package release requirements, host release admission, and source locks.
let
  lib = import ../../lib {system = "x86_64-linux";};
  fixturePayload = import ./_fixture-payload.nix;
  dependencies = import ../../lib/packages/module-dependencies.nix;
  artifacts = import ../../lib/packages/artifacts.nix {};
  modules = import ../../lib/build/package-modules.nix {};
  package = name: source: {
    type = "derivation";
    pname = name;
    version = "9.2.0";
    system = "x86_64-linux";
    outPath = fixturePayload name;
    module = builtins.path {
      path = source;
      name = "${name}-module";
    };
    deploymentArtifact = fixturePayload "${name}-deployment";
  };
  signed = value: value // {deployment = artifacts.envelope value;};
  interface = signed (package "release-interface" ./release-compatibility/interface);
  consumer = signed ((package "release-consumer" ./release-compatibility/consumer)
    // {
      moduleDeps = [
        {
          package = interface;
          exact = true;
        }
      ];
    });
  secondary = signed (package "release-secondary" ./release-compatibility/secondary);
  compatible = range: {
    package = interface;
    packageVersion = range;
  };
  requester = dependency: signed (consumer // {moduleDeps = [dependency];});
  rejects = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
  evaluate = packages:
    lib.evalPackageModules {
      scope = ["test" "release-compatibility"];
      inherit packages;
    };
  moduleless = signed (
    (builtins.removeAttrs (package "moduleless-requester" ./release-compatibility/consumer) ["module"])
    // {
      moduleDeps = [
        (compatible "^9.0")
        {
          package = secondary;
          exact = true;
        }
      ];
      osVersion = "^0.1";
    }
  );
  exactRequester = consumer;
  lock = import ../../lib/packages/resolution-lock.nix {
    packages = [moduleless exactRequester];
  };
  lockContext = builtins.getContext (builtins.toJSON lock);
  payloadRoots =
    map (value: builtins.unsafeDiscardStringContext (builtins.toString value))
    [moduleless exactRequester interface secondary];
  sourceRoots =
    map (value: builtins.unsafeDiscardStringContext (builtins.toString value))
    [interface.module secondary.module moduleless.deploymentArtifact exactRequester.deploymentArtifact];
  modulelessEdges = builtins.filter (edge: edge.requester.name == moduleless.pname) lock.edges;
  exactEdges = builtins.filter (edge: edge.requester.name == exactRequester.pname) lock.edges;
  hostRelease = {
    name = "aos";
    version = "0.1.8";
  };
  admit = release: packages:
    lib.evalPackageModules {
      scope = ["test" "release-compatibility"];
      inherit packages;
      osRelease = release;
      enforceOsRequirements = true;
    };
in {
  defaultPresenceDoesNotEvaluateValues = let
    reference =
      (lib.evalPackageModules {
        scope = ["test" "default-presence"];
        modules = [
          {
            options.example = lib.mkOption {
              type = lib.types.str;
              default = throw "documentation must not evaluate defaults";
            };
            aos.abilities.example.operations.ensure = {
              input.options.optional = lib.mkOption {
                type = lib.types.str;
                default = throw "interface checks must not evaluate input defaults";
              };
              input.options.required = lib.mkOption {type = lib.types.str;};
              result.options.path = lib.mkOption {type = lib.types.str;};
            };
          }
        ];
      }).documentation;
  in
    assert reference.abilities.example.ensure.inputDefaults == [["optional"]];
    assert (builtins.head (builtins.filter (option: option.path == ["example"]) reference.options)).hasDefault; true;

  matchingPackageSeed = assert (evaluate [(requester (compatible "^9.0"))]).documentation.moduleRequirements
  == [
    {
      owner = consumer.pname;
      package = interface.pname;
      packageVersion = "^9.0";
    }
  ]; true;
  incompatiblePackageSeed = assert rejects (evaluate [(requester (compatible "^1.0"))]); true;
  exactSeedHasNoRequirement = assert (evaluate [exactRequester]).documentation.moduleRequirements == []; true;
  modulelessReferenceRequirements = let
    document = (evaluate [moduleless]).documentation;
  in
    assert document.moduleRequirements
    == [
      {
        owner = moduleless.pname;
        package = interface.pname;
        packageVersion = "^9.0";
      }
    ];
    assert document.osRequirements
    == [
      {
        owner = moduleless.pname;
        osVersion = "^0.1";
      }
    ]; true;
  envelopeRetainsOsRequirement = assert moduleless.deployment.osVersion == "^0.1"; true;
  absentOsRequirementIsOmitted = assert !(interface.deployment ? osVersion); true;
  matchingHostRelease = assert (admit hostRelease [moduleless]).documentation.osRequirements
  == [
    {
      owner = moduleless.pname;
      osVersion = "^0.1";
    }
  ]; true;
  incompatibleHostRelease = assert rejects (admit {
    name = "aos";
    version = "0.2.0";
  } [moduleless]); true;
  absentHostRelease = assert rejects (admit null [moduleless]); true;
  unrequiredHostRelease = assert (admit null [interface]).documentation.osRequirements == []; true;
  inheritedOsRequirements = let
    dependent = signed (consumer // {moduleDeps = [moduleless];});
  in
    assert rejects (admit null [dependent]); true;
  explicitOsRequirements = assert rejects (lib.evalPackageModules {
    scope = ["test" "release-compatibility"];
    packages = [interface];
    osRequirements = [
      {
        owner = "external-package";
        osVersion = "^0.2";
      }
    ];
    osRelease = hostRelease;
    enforceOsRequirements = true;
  }); true;
  removedAbilityVersionRejected = assert rejects (lib.evalPackageModules {
    scope = ["test" "release-compatibility"];
    packages = [interface];
    operatorModules = [{aos.abilities.versioned.version = "1.4.2";}];
  }); true;
  removedVersionOwnerRejected = assert rejects (lib.evalPackageModules {
    scope = ["test" "release-compatibility"];
    packages = [interface];
    operatorModules = [{aos.abilities.versioned.versionOwner = interface.pname;}];
  }); true;
  removedExportRecordRejected = assert rejects (modules.canonicalize [
    ((builtins.head (modules.closure [interface])) // {abilityExports.versioned.version = "1.4.2";})
  ]); true;
  exactOnlyHasNoLock = assert (import ../../lib/packages/resolution-lock.nix {packages = [exactRequester];}) == null; true;
  lockPreservesAllEdges = assert lock.schema == "aos.package.resolution-lock";
  assert builtins.length lock.edges == 3;
  assert builtins.length modulelessEdges == 2 && builtins.length exactEdges == 1;
  assert (builtins.head exactEdges).requirement == artifacts.moduleReference interface;
  assert (builtins.head exactEdges).selected == artifacts.moduleReference interface; true;
  compatibleLockEdge = let
    edge = builtins.head (builtins.filter (edge: edge.requirement ? package) modulelessEdges);
  in
    assert edge.requirement
    == {
      package = artifacts.moduleReference interface;
      packageVersion = "^9.0";
    };
    assert edge.selected == artifacts.moduleReference interface; true;
  modulelessRequesterRetained = assert lock.requesters.${builtins.unsafeDiscardStringContext (builtins.toString moduleless)} == builtins.toString moduleless.deploymentArtifact;
  assert builtins.length (builtins.attrNames lock.requesters) == 2; true;
  sourceOnlyLockContexts = assert builtins.all (root: lockContext ? ${root}) sourceRoots;
  assert builtins.all (root: !(lockContext ? ${root})) payloadRoots; true;
  duplicateExactEdgesRejected = assert rejects (modules.resolved [
    (consumer
      // {
        moduleDeps = [
          {
            package = interface;
            exact = true;
          }
          {
            package = interface;
            exact = true;
          }
        ];
      })
  ]); true;
  duplicateMixedEdgesRejected = let
    duplicate =
      consumer
      // {
        moduleDeps = [
          {
            package = interface;
            exact = true;
          }
          (compatible "^9.0")
        ];
      };
  in
    assert rejects (modules.resolved [duplicate]);
    assert rejects (artifacts.envelope duplicate); true;
  malformedRequirements = assert rejects (dependencies.normalize {package = interface;});
  assert rejects (dependencies.normalize {
    package = interface;
    packageVersion = "^9";
    unchecked = true;
  });
  assert rejects (dependencies.normalize {
    package = interface;
    packageVersion = "not-a-range";
  }); true;
  removedAbilityRequirementRejected = assert rejects (dependencies.normalize {
    package = interface;
    abilities.versioned = "^1.4";
  });
  assert rejects (dependencies.normalize {
    package = interface;
    packageVersion = "^9.0";
    abilities.versioned = "^1.4";
  }); true;
}
