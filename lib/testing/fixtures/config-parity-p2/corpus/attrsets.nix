let
  defaults = {
    enabled = false;
    port = 80;
  };
  configured = defaults // {
    enabled = true;
    port = 8443;
  };
in {
  manifest = {
    inherit (configured) enabled port;
    names = builtins.attrNames configured;
    hasPort = configured ? port;
  };
  optionWrites = [];
}
