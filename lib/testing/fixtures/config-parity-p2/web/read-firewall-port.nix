config: let
  alias = config;
  root = builtins.getAttr "firewall" alias;
in
  builtins.getAttr "port" root
