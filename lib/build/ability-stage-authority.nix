##! Canonical planning inputs for one explicitly composed build stage.
##!
##! The target module fixed point supplies only source-level selection intent.
##! The AOS package runtime resolves exact package and artifact identities from
##! the selected contract companions, validates the common ability model, and
##! writes the canonical desired and authenticated-policy documents.
{
  lib,
  mkDerivation,
  packageRuntime,
}: {
  pname,
  stage,
  authority,
  key,
  platform,
  selectionIntent,
  packageContracts,
}: let
  packageContractPaths = builtins.sort (left: right: left < right) (
    lib.unique (builtins.map builtins.toString packageContracts)
  );
  specification = builtins.toFile
    "${pname}-ability-authority-spec.json"
    (builtins.unsafeDiscardStringContext (builtins.toJSON {
      schema = "aos.ability.build-stage-authority/v1";
      inherit stage authority key platform;
      selection_intent = builtins.toString selectionIntent;
      packages = packageContractPaths;
    }));
  authorityDocuments = mkDerivation {
    pname = "${pname}-ability-authority";
    version = "1";
    src = null;
    buildDeps = [packageRuntime selectionIntent] ++ packageContracts;
    phases = [
      {
        name = "author";
        script = ''
          ${packageRuntime}/bin/aos-package-runtime \
            __ability-author-build-stage \
            --spec ${lib.escapeShellArg (builtins.toString specification)} \
            --out "$out"
        '';
      }
    ];
    outputChecks.out = {};
    preferLocalBuild = true;
    allowSubstitutes = false;
  };
in {
  desiredInput = "${authorityDocuments}/desired.json";
  authenticatedPolicySet = "${authorityDocuments}/policy.json";
  inherit authorityDocuments;
}
