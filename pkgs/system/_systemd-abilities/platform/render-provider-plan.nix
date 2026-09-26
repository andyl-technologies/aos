##! Resolves symbolic provider artifacts before rendering one static systemd plan.
{
  runCommand,
  providerPackage,
}: plan: let
  selectorPaths = builtins.toJSON plan.selectors;
  artifactPaths = builtins.map (selector: selector.path) plan.selectors;
in
  runCommand (builtins.unsafeDiscardStringContext plan.name) {
    realization = plan.input;
    inherit selectorPaths;
    outputChecks = {};
    exportReferencesGraph.renderGraph = artifactPaths;
  } ''
    ${providerPackage}/bin/aos-systemd-provider resolve-render-input \
      "$NIX_ATTRS_JSON_FILE" resolved-realization.json
    ${providerPackage}/bin/aos-systemd-provider render \
      resolved-realization.json "$NIX_ATTRS_JSON_FILE"
  ''
