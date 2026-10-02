##! Checks authored version shorthand and generated package release requirements.
{pkgs}: let
  lib = import ../../lib {system = pkgs.stdenv.hostPlatform.system;};
  versions = import ../../lib/packages/version.nix;
  dependencies = import ../../lib/packages/module-dependencies.nix;
  rejects = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
  normalize = authored: exact: requirement:
    versions.normalize authored
    == {
      version = exact;
      versionRequirement = requirement;
    };
  recipe = authored: extra:
    pkgs.mkDerivation ({
        pname = "version-shorthand-fixture";
        version = authored;
        src = null;
        phases = [];
        module = ./release-compatibility/interface;
      }
      // extra);
  bare = recipe "1.2.3" {};
  caret = recipe "^1.2.3" {};
  tilde = recipe "~1.2.3" {};
  equal = recipe "=1.2.3" {};
  legacy = recipe "2026-09" {};
  multiOutput = recipe "~1.2.3" {outputs = ["out" "dev"];};
  rename = tilde.overrideAttrs (previous: {
    pname = "renamed-shorthand-fixture";
    authoredVersionForTest = previous.version;
  });
  changedVersion = tilde.overrideAttrs (_: {version = "2.0.0";});
  consumer = dependency:
    pkgs.mkDerivation {
      pname = "version-shorthand-consumer";
      version = "1.0.0";
      src = null;
      phases = [];
      moduleDeps = [dependency];
    };
  moduleReference = bare.deployment.module;
  inferred = consumer tilde;
  pinned = consumer {
    package = tilde;
    exact = true;
  };
  overridden = consumer {
    package = tilde;
    packageVersion = "^1.0";
  };
  moduleless = pkgs.mkDerivation {
    pname = "moduleless-shorthand-fixture";
    version = "~1.2.3";
    src = null;
    phases = [];
  };
  modulelessArtifact = moduleless.deployment.package;
  modulelessRelease = {
    name = moduleless.pname;
    version = moduleless.version;
    versionRequirement = moduleless.versionRequirement;
  };
  replay = packageArtifacts: packageReleases:
    (lib.evalPackageModules {
      scope = ["test" "retained-release-policy"];
      inherit packageArtifacts packageReleases;
    }).documentation.packages;
  go = pkgs.mkGoPackage {
    pname = "go-version-shorthand-fixture";
    version = "~1.2.3";
    src = ./fixtures/inert-payload;
  };
  goRename = go.overrideAttrs (_: {pname = "renamed-go-version-fixture";});
  cargo = pkgs.mkCargoPackage {
    pname = "cargo-version-shorthand-fixture";
    cargoDeps = ./fixtures/inert-payload;
    version = "=1.2.3";
    src = ./fixtures/inert-payload;
  };
in {
  strictDefaultsToCaret = assert normalize "1.2.3" "1.2.3" "^1.2.3"; true;
  shorthandOperators = assert normalize "^1.2.3" "1.2.3" "^1.2.3";
  assert normalize "~1.2.3" "1.2.3" "~1.2.3";
  assert normalize "=1.2.3" "1.2.3" "=1.2.3"; true;
  prereleaseAndBuild = assert normalize "~1.2.3-rc.1+build.7" "1.2.3-rc.1+build.7" "~1.2.3-rc.1+build.7"; true;
  nonSemverIsExactOnly = assert normalize "2026-09" "2026-09" null;
  assert normalize "1.2" "1.2" null;
  assert normalize "v1.2.3" "v1.2.3" null;
  assert normalize "1.02.3" "1.02.3" null; true;
  invalidShorthandRejected = assert builtins.all (authored: rejects (versions.normalize authored))
  ["^1.2" "~v1.2.3" "=1.02.3" "^^1.2.3" "^~1.2.3" "~=1.2.3" ">=1.2.3" "1.2.3 || 2.0.0"]; true;
  invalidUpstreamCoordinatesRejected = assert builtins.all (authored: rejects (versions.normalize authored))
  ["" "." ".." "-1" "_label" (builtins.concatStringsSep "" (builtins.genList (_: "a") 256))]; true;
  normalizedRecipeIdentity = assert bare.version == "1.2.3" && bare.versionRequirement == "^1.2.3";
  assert tilde.version == "1.2.3" && tilde.versionRequirement == "~1.2.3";
  assert equal.version == "1.2.3" && equal.versionRequirement == "=1.2.3";
  assert tilde.name == "version-shorthand-fixture-1.2.3"; true;
  policyDoesNotChangePayload = assert bare.drvPath == caret.drvPath;
  assert caret.drvPath == tilde.drvPath && tilde.drvPath == equal.drvPath; true;
  envelopeAndDocumentationAreNormalized = assert tilde.deployment.package.version == "1.2.3";
  assert tilde.documentation.packages
  == [
    {
      name = tilde.pname;
      version = "1.2.3";
      versionRequirement = "~1.2.3";
    }
  ]; true;
  companionsRetainPolicy = assert tilde.deployment.versionRequirement == "~1.2.3";
  assert equal.deployment.versionRequirement == "=1.2.3";
  assert !(legacy.deployment ? versionRequirement);
  assert caret.deploymentArtifact.drvPath != tilde.deploymentArtifact.drvPath; true;
  inferredRequirementsUseAuthoredPolicy = assert inferred.deployment.moduleDependencies
  == [
    {
      package = moduleReference;
      packageVersion = "~1.2.3";
    }
  ];
  assert inferred.documentation.moduleRequirements
  == [
    {
      owner = inferred.pname;
      package = tilde.pname;
      packageVersion = "~1.2.3";
    }
  ]; true;
  explicitRangeOverridesPolicy = assert overridden.deployment.moduleDependencies
  == [
    {
      package = moduleReference;
      packageVersion = "^1.0";
    }
  ]; true;
  exactWrapperPinsSource = assert pinned.deployment.moduleDependencies == [moduleReference];
  assert pinned.documentation.moduleRequirements == []; true;
  legacyDependencyRemainsExact = assert (dependencies.normalize legacy).requirements == null; true;
  rawStrictDependencyInfersCaret = assert (dependencies.normalize {version = "1.2.3";}).requirements == {packageVersion = "^1.2.3";}; true;
  exactWrapperRejectsOtherFields = assert rejects (dependencies.normalize {
    package = bare;
    exact = false;
  });
  assert rejects (dependencies.normalize {
    package = bare;
    exact = true;
    packageVersion = "^1.0";
  }); true;
  generatedRequirementCannotBeAuthored = assert rejects (recipe "1.2.3" {versionRequirement = "~1.2.3";}).version; true;
  overridesPreserveAuthoring = assert rename.version == "1.2.3" && rename.versionRequirement == "~1.2.3";
  assert rename.authoredVersionForTest == "~1.2.3";
  assert changedVersion.version == "2.0.0" && changedVersion.versionRequirement == "^2.0.0"; true;
  selectedOutputsPreservePolicy = assert multiOutput.dev.version == "1.2.3";
  assert multiOutput.dev.versionRequirement == "~1.2.3";
  assert multiOutput.dev.deployment.package.version == "1.2.3"; true;
  modulelessReplayRetainsPolicy = assert replay [modulelessArtifact] [modulelessRelease] == [modulelessRelease];
  assert moduleless.documentation.packages == [modulelessRelease]; true;
  replayInfersCaretWhenPolicyIsOmitted = assert replay [modulelessArtifact] [
    (builtins.removeAttrs modulelessRelease ["versionRequirement"])
  ]
  == [(modulelessRelease // {versionRequirement = "^1.2.3";})]; true;
  replayRejectsUnknownReleaseFields = assert rejects (replay [modulelessArtifact] [
    (modulelessRelease // {unchecked = true;})
  ]); true;
  identicalReplayMetadataIsDeduplicated = assert replay [modulelessArtifact modulelessArtifact] [modulelessRelease modulelessRelease] == [modulelessRelease]; true;
  replayRejectsUnselectedRelease = assert rejects (replay [modulelessArtifact] [
    (modulelessRelease
      // {
        version = "1.3.0";
        versionRequirement = "~1.3.0";
      })
  ]); true;
  replayRejectsUnboundPolicy = assert rejects (replay [modulelessArtifact] [
    (modulelessRelease // {versionRequirement = "~1.2.4";})
  ]); true;
  replayRejectsConflictingPolicies = assert rejects (replay [modulelessArtifact] [
    modulelessRelease
    (modulelessRelease // {versionRequirement = "^1.2.3";})
  ]); true;
  replayRejectsConflictingArtifactVersions = assert rejects (replay [
    modulelessArtifact
    (modulelessArtifact // {version = "2.0.0";})
  ] [modulelessRelease]); true;
  moduleProjectionRejectsConflictingPolicy = assert rejects
  (lib.evalPackageModules {
    scope = ["test" "conflicting-module-release"];
    packages = [tilde];
    packageReleases = [
      {
        name = tilde.pname;
        version = "1.2.3";
        versionRequirement = "^1.2.3";
      }
    ];
  }).documentation.packages; true;
  languageBuildersPreservePolicy = assert go.version == "1.2.3" && go.versionRequirement == "~1.2.3";
  assert goRename.version == "1.2.3" && goRename.versionRequirement == "~1.2.3";
  assert cargo.version == "1.2.3" && cargo.versionRequirement == "=1.2.3"; true;
}
