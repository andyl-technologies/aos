##! Applies inline fleet overrides through the ephemeral system extension API.
{mkSystem}: arguments: let
  modules =
    if builtins.isList arguments
    then arguments
    else arguments.modules or [];
  parameters =
    if builtins.isList arguments
    then {}
    else builtins.removeAttrs arguments ["modules"];
  sources = builtins.filter builtins.isPath modules;
  overrides = builtins.filter (module: !builtins.isPath module) modules;
  system = mkSystem (parameters // {modules = sources;});
in
  if overrides == []
  then system
  else system.extendModules {modules = overrides;}
