##! Locks build-selected module dependencies for exact deployment replay.
{packages}: let
  modules = import ../build/package-modules.nix {};
  dependencies = import ./module-dependencies.nix;
  artifacts = import ./artifacts.nix {};
  entries = modules.resolved packages;
  requesters = builtins.filter (entry: (entry.package.moduleDeps or []) != []) entries;
  edges = builtins.concatLists (map (entry:
    map (dependency: {
      requester = artifacts.metadata entry.identity.artifact;
      requirement = dependencies.reference artifacts.moduleReference dependency;
      selected = artifacts.moduleReference (dependencies.seed dependency);
    })
    entry.package.moduleDeps)
  requesters);
  hasRanges = builtins.any (edge: edge.requirement ? package) edges;
in
  if !hasRanges
  then null
  else {
    schema = "aos.package.resolution-lock";
    inherit edges;
    # Companion roots retain original declarations even for moduleless packages.
    # Artifact identities above carry no payload context in source-only builds.
    requesters = builtins.listToAttrs (map (entry: {
        name = builtins.unsafeDiscardStringContext entry.identity.artifact.path;
        value = builtins.toString entry.package.deploymentArtifact;
      })
      requesters);
  }
