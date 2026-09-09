##! Inventories exported tools, preserving store context for sandbox inputs.
{buildPlatform}: let
  bootstrap = import ../../stdenv/bootstrap {inherit buildPlatform;};
  tiers =
    {inherit bootstrap;}
    // import ../../stdenv/toolchains {
      inherit bootstrap buildPlatform;
      hostPlatform = buildPlatform;
      targetPlatform = buildPlatform;
      exportTiers = true;
    };
  outputs = attrs:
    builtins.listToAttrs (builtins.concatMap (name: let
      value = attrs.${name};
    in
      if builtins.isAttrs value && (value.type or null) == "derivation"
      then
        [
          {
            inherit name;
            value = toString value;
          }
        ]
        ++ map (output: {
          name = "${name}.${output}";
          value = toString value.${output};
        }) (builtins.filter (output: output != "out") (value.outputs or ["out"]))
      else []) (builtins.attrNames attrs));
in
  builtins.mapAttrs (_: outputs) tiers
