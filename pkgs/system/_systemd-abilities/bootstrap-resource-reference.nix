##! Projects declared resource addresses without claiming producer readiness.
{
  config,
  lib,
}: let
  project = reference:
    if !builtins.isAttrs reference
    then reference
    else let
      identity = reference.identity or [];
      suffix = lib.drop (builtins.length identity - 3) identity;
      ability = builtins.elemAt suffix 0;
      operation = builtins.elemAt suffix 1;
      name = builtins.elemAt suffix 2;
      output = reference.output;
      supported = builtins.elem [ability operation output] [
        ["serviceManagement" "realize" "resource"]
        ["network" "ready" "resource"]
        ["configuration" "file" "path"]
        ["identity" "group" "name"]
        ["identity" "principal" "name"]
      ];
      producer = config.aos.abilities.${ability}.operations.${operation}.effects.${name} or null;
      selection = producer.input.instantiation or null;
      serviceIdentity = {
        inherit (producer.input) service;
        instance = name;
        manager_identity = producer.input.manager_identity or null;
        instantiation =
          if selection != null && selection.kind == "instance"
          then selection // {template_resource = project selection.template_resource;}
          else selection;
      };
    in
      if !lib.types.effectOutput.check reference || builtins.length identity < 4
      then throw "An image resource address must reference a declared output."
      else if !supported || producer == null || !producer.enable || producer.contract.identity != identity || producer.outputs.${output}.schema != reference.schema
      then throw "An image resource address refers to an absent, foreign, or incompatible producer."
      else if ability == "configuration"
      then producer.input.path
      else if ability == "identity"
      then producer.input.name
      else if ability == "network"
      then
        if producer.input.required
        then "systemd-networkd.service"
        else "sysinit.target"
      # Preserve the identity inputs for the canonical Python renderer, including
      # its byte escaping of template instances. This is an address, not a receipt.
      else {image_service_identity = serviceIdentity;};
in
  project
