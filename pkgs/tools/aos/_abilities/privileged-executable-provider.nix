##! Lowers privileged executable requests to the selected filesystem provider.
{
  config,
  lib,
  ...
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  implementationAlias = "privileged-executable";
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
  };
  childOutput = children: key: output:
    children.${key}.outputs.${output}.value
    or (throw "privileged executable provider requires ${key}.${output}");
  filesystemRequest = {
    key,
    slot,
    parameters,
    ownerRequest ? null,
  }: {
    name = key;
    value =
      {
        requirement = "filesystem-entry";
        scope = [key];
        inherit slot parameters;
      }
      // lib.optionalAttrs (ownerRequest != null) {
        owner_request = ownerRequest;
      };
  };
  rootRequest = filesystemRequest {
    key = "wrapper-root";
    slot = "wrapper-root";
    parameters = {
      name = "wrappers";
      entry.kind = "directory";
      destination = "/run/wrappers";
      owner = "root";
      group = "root";
      mode = "0755";
      prerequisites = [];
    };
  };
  binRequest = children:
    filesystemRequest {
      key = "wrapper-bin";
      slot = "wrapper-bin";
      parameters = {
        name = "wrapper-bin";
        entry.kind = "directory";
        destination = "/run/wrappers/bin";
        owner = "root";
        group = "root";
        mode = "0755";
        prerequisites = [(childOutput children "wrapper-root" "resource")];
      };
    };
  bindingFor = bindings: requestName: let
    matches = builtins.filter (
      binding: binding.request == requestName
    ) (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a privileged executable request must have exactly one selected binding";
  entryKey = binding: "entry-${binding.slot}";
  entryRequest = children: entry:
    filesystemRequest {
      key = entry.key;
      slot = entry.binding.slot;
      ownerRequest = entry.requestName;
      parameters = {
        inherit (entry.request.parameters) name owner group mode;
        entry = {
          kind = "copied-file";
          source = {
            kind = "artifact-file";
            reference = entry.request.parameters.source;
          };
          inherit (entry.request.parameters) maximum_size_bytes;
        };
        destination = "/run/wrappers/bin/${entry.request.parameters.name}";
        prerequisites = [(childOutput children "wrapper-bin" "resource")];
      };
    };
  provide = {
    bindings,
    children,
    requests,
    ...
  }: let
    entries = builtins.map (requestName: let
      binding = bindingFor bindings requestName;
    in {
      inherit requestName binding;
      request = requests.${requestName};
      key = entryKey binding;
    }) (builtins.attrNames requests);
    wrapperRootReady = children ? wrapper-root;
    wrapperBinReady = children ? wrapper-bin;
    entryRequests =
      if wrapperBinReady
      then builtins.listToAttrs (builtins.map (entry: entryRequest children entry) entries)
      else {};
    outputs = builtins.listToAttrs (builtins.concatMap (entry:
      lib.optional (builtins.hasAttr entry.key children) {
        name = entry.requestName;
        value = {
          planned-path = childOutput children entry.key "planned-path";
          resource = childOutput children entry.key "resource";
        };
      })
    entries);
  in
    emptyProvision
    // {
      inherit outputs;
      requests =
        {${rootRequest.name} = rootRequest.value;}
        // lib.optionalAttrs wrapperRootReady {${(binRequest children).name} = (binRequest children).value;}
        // entryRequests;
    };
in {
  config.aos.abilities.implementations.${implementationAlias}.provide = provide;
}
