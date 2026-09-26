##! Resolves one declared request output from its selected interface and methods.
{
  interface,
  methods,
  outputName,
  context,
}: let
  aggregate = interface.outputs.${outputName} or null;
  methodOutputs = builtins.concatMap (methodName: let
    method = interface.methods.${methodName}
      or (throw "${context} selects absent method '${methodName}'");
  in
    if builtins.hasAttr outputName method.outputs
    then [method.outputs.${outputName}]
    else [])
  methods;
  candidates =
    if aggregate != null
    then [aggregate]
    else methodOutputs;
in
  if builtins.length candidates != 1
  then throw "${context} must name one exact authorized output"
  else builtins.head candidates
