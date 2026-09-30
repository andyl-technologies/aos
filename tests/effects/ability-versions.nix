##! Checks version ownership, authenticated exports, compatibility, and source locks.
let
  lib = import ../../lib {system = "x86_64-linux";};
  fixturePayload = import ./_fixture-payload.nix;
  contracts = import ../../lib/packages/ability-contracts.nix {inherit lib;};
  dependencies = import ../../lib/packages/module-dependencies.nix;
  artifacts = import ../../lib/packages/artifacts.nix {};
  modules = import ../../lib/build/package-modules.nix {};
  rawModules = import ../../lib/build/package-modules.nix {verifyMetadata = false;};
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
  interface = package "version-interface" ./ability-versions/interface;
  consumer =
    package "version-consumer" ./ability-versions/consumer
    // {
      moduleDeps = [interface];
    };
  secondary = package "version-secondary" ./ability-versions/secondary;
  raw =
    package "raw-interface" ./ability-versions/raw
    // {
      # Module provenance still validates the ordinary output locator. Projecting
      # declarations must not inspect the payload build or its signed companions.
      drvPath = throw "Contract projection forced a payload build.";
      deployment = throw "Contract projection forced signed metadata.";
      deploymentArtifact = throw "Contract projection forced a source companion.";
    };
  declarationContracts = contracts.forPackages [consumer];
  signed = value:
    value
    // {
      deployment =
        artifacts.envelope value
        // {
          abilityExports = contracts.exports value;
        };
    };
  signedInterface = signed interface;
  evaluated = lib.evalPackageModules {
    scope = ["test" "ability-versions"];
    packages = [signedInterface];
  };
  rejects = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
  mismatched =
    signedInterface
    // {
      deployment =
        signedInterface.deployment
        // {
          abilityExports.versioned.version = "1.4.3";
        };
    };
  evaluate = value:
    lib.evalPackageModules {
      scope = ["test" "ability-versions"];
      packages = [value];
    };
  compatible = abilityRange: packageRange: {
    package = interface;
    abilities.versioned = abilityRange;
    packageVersion = packageRange;
  };
  requester = dependency: consumer // {moduleDeps = [dependency];};
  seedsMatch = value: contracts.checkSeeds [value] (contracts.forPackages [value]);
  moduleless =
    builtins.removeAttrs (package "moduleless-requester" ./ability-versions/consumer) ["module"]
    // {
      moduleDeps = [(compatible "^1.4" "^9.0") secondary];
    };
  exactRequester = consumer // {moduleDeps = [interface];};
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
  duplicateOwner = package "other-version-owner" ./ability-versions/interface;
in {
  ownedExports = assert contracts.exports interface == {versioned.version = "1.4.2";};
  assert contracts.exports consumer == {}; true;
  declarationOwner = assert declarationContracts.versioned
  == {
    version = "1.4.2";
    owner = "version-interface";
  }; true;
  rawProjection = assert contracts.exports raw == {raw.version = "0.3.0";}; true;
  rawRecordProjection = assert contracts.fromRecords (rawModules.closure [raw])
  == {
    raw = {
      version = "0.3.0";
      owner = "raw-interface";
    };
  }; true;
  independentVersions = assert signedInterface.version == "9.2.0";
  assert evaluated.config.aos.abilities.versioned.version == "1.4.2";
  assert evaluated.config.aos.abilities.versioned.versionOwner == signedInterface.pname; true;
  authenticatedExports = assert contracts.checkRecords (modules.closure [signedInterface]) evaluated.config; true;
  alteredExportsRejected = assert rejects (evaluate mismatched); true;
  operatorCannotChangeContractRelease = assert rejects (lib.evalPackageModules {
    scope = ["test" "ability-versions"];
    packages = [signedInterface];
    operatorModules = [{aos.abilities.versioned.version = lib.mkForce "2.0.0";}];
  }); true;
  missingExportsRejected = assert rejects (evaluate interface); true;
  unknownExportRejected = assert rejects (evaluate (signedInterface
    // {
      deployment =
        signedInterface.deployment
        // {
          abilityExports.unknown.version = "1.0.0";
        };
    })); true;
  oneOwnerPerScope = assert rejects (contracts.forPackages [interface duplicateOwner]); true;
  matchingSeeds = assert seedsMatch (requester (compatible "^1.4" "^9.0")); true;
  packageOnlyRequirement = assert seedsMatch (requester {
    package = interface;
    packageVersion = "^9";
  }); true;
  incompatibleAbilitySeed = assert rejects (seedsMatch (requester (compatible "^2.0" "^9.0"))); true;
  incompatiblePackageSeed = assert rejects (seedsMatch (requester (compatible "^1.4" "^1.0"))); true;
  unknownAbilitySeed = assert rejects (seedsMatch (requester {
    package = interface;
    abilities.unknown = "*";
  })); true;
  rangeOwnership = assert contracts.requirements [moduleless]
  == [
    {
      owner = moduleless.pname;
      package = interface.pname;
      abilities.versioned = "^1.4";
      packageVersion = "^9.0";
    }
  ]; true;
  modulelessReferenceRequirements = let
    document =
      (evaluate (moduleless
        // {
          moduleDeps = [((compatible "^1.4" "^9.0") // {package = signedInterface;}) (signed secondary)];
        })).documentation;
  in
    assert document.moduleRequirements == contracts.requirements [moduleless];
    assert document.abilityContracts.versioned.owner == interface.pname; true;
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
      abilities.versioned = "^1.4";
      packageVersion = "^9.0";
    };
    assert edge.selected == artifacts.moduleReference interface; true;
  modulelessRequesterRetained = assert lock.requesters.${builtins.unsafeDiscardStringContext (builtins.toString moduleless)} == builtins.toString moduleless.deploymentArtifact;
  assert builtins.length (builtins.attrNames lock.requesters) == 2; true;
  sourceOnlyLockContexts = assert builtins.all (root: lockContext ? ${root}) sourceRoots;
  assert builtins.all (root: !(lockContext ? ${root})) payloadRoots; true;
  duplicateExactEdgesRejected = assert rejects (modules.resolved [
    (consumer // {moduleDeps = [interface interface];})
  ]); true;
  duplicateMixedEdgesRejected = let
    duplicate =
      consumer
      // {
        moduleDeps = [interface (compatible "^1.4" "^9.0")];
      };
  in
    assert rejects (modules.resolved [duplicate]);
    assert rejects (artifacts.envelope duplicate); true;
  malformedRequirements = assert rejects (dependencies.normalize {package = interface;});
  assert rejects (dependencies.normalize {
    package = interface;
    abilities.versioned = "^1.4";
    unchecked = true;
  });
  assert rejects (dependencies.normalize {
    package = interface;
    abilities.versioned = "not-a-range";
  }); true;
}
